//! Trusted, read-only scans. Candidate code/configuration never executes here.
//!
//! Run on a dedicated ephemeral scanner worker, never alongside native candidate
//! jobs. Docker is a local trusted service. Source-bearing containers have no
//! network, host credentials, Docker socket, writable policy, or writable
//! evidence mount. This is the behaviour of the former `scripts/security/scan.py`
//! (receipt schema `busbar.security-scans/1`), byte for byte.
use crate::isotime::aware_utc_micros;
use crate::json::{self, ParseError, Value};
use crate::sha256::{self, Sha256};
use std::cmp::Ordering as CmpOrdering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DIAGNOSTIC_LIMIT: usize = 100;
const REPORT_LIMIT: u64 = 128 * 1024 * 1024;
pub const SAFE_FAILURE: &str =
    "security scans failed or could not run; inspect the safe receipt and worker prerequisites";
pub const SUCCESS: &str = "security scans passed; source-bound receipt retained";

/// The former scanner's exception classes. Inside one scan, `Refuse`
/// (ValueError/KeyError/TypeError) records a failed step and the remaining
/// scans still run; `Abort` (OSError, subprocess timeout, recursion) stops
/// the run. Every failure exits 1 after writing the receipt when one exists.
#[derive(Debug, PartialEq)]
pub enum Fail {
    Refuse(&'static str),
    Abort(&'static str),
}
type Result<T> = std::result::Result<T, Fail>;

fn require(ok: bool, message: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Fail::Refuse(message))
    }
}
fn os<T>(value: std::io::Result<T>) -> Result<T> {
    value.map_err(|_| Fail::Abort("filesystem or process operation failed"))
}
fn parse(data: &[u8]) -> Result<Value> {
    json::parse_cpython(data).map_err(|error| match error {
        ParseError::Invalid(_) => Fail::Refuse("invalid JSON"),
        ParseError::TooDeep => Fail::Abort("JSON nesting exceeds recursion limit"),
    })
}
/// `json.loads(path.read_text())`: text decoding keeps a BOM, which JSON refuses.
fn read_text_json(path: &Path) -> Result<Value> {
    let data = os(fs::read(path))?;
    require(!data.starts_with(b"\xef\xbb\xbf"), "invalid JSON")?;
    parse(&data)
}
/// `Path.read_text()`: UTF-8 with universal newlines.
fn read_text(path: &Path) -> Result<String> {
    let text = String::from_utf8(os(fs::read(path))?).map_err(|_| Fail::Refuse("invalid UTF-8"))?;
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}
fn key<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or(Fail::Refuse("missing key"))
}
fn key_str<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    key(value, name)?
        .as_str()
        .ok_or(Fail::Refuse("non-string value"))
}

pub fn digest(path: &Path) -> Result<String> {
    let mut stream = os(File::open(path))?;
    let mut sha = Sha256::default();
    let mut buffer = vec![0; 1 << 16];
    loop {
        let n = os(stream.read(&mut buffer))?;
        if n == 0 {
            return Ok(sha.hex());
        }
        sha.update(&buffer[..n]);
    }
}

// Fixed patterns of the former scanner (all ASCII, so Python's code-point
// lengths equal byte lengths whenever the pattern can match).
fn class(value: &str, allowed: impl Fn(u8) -> bool) -> bool {
    value.bytes().all(allowed)
}
fn alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}
fn hex_lower(value: &str, count: usize) -> bool {
    value.len() == count && class(value, |c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}
fn location_pattern(value: &str) -> bool {
    value.len() <= 512 && !value.is_empty() && class(value, |c| alnum(c) || b"_.+/-".contains(&c))
}
fn check_id_pattern(value: &str) -> bool {
    value.len() <= 256 && !value.is_empty() && class(value, |c| alnum(c) || b"_.-".contains(&c))
}
/// `[0-9][A-Za-z0-9.+:~_-]*`, at most 64.
fn version(value: &str) -> bool {
    value.len() <= 64
        && value.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && class(value, |c| alnum(c) || b".+:~_-".contains(&c))
}
fn numeric_run(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len()) && class(value, |c| c.is_ascii_digit())
}
/// `CVE-[0-9]{4}-[0-9]{4,19}|RUSTSEC-[0-9]{4}-[0-9]{4}|GHSA-x{4}-x{4}-x{4}`.
fn advisory(value: &str) -> bool {
    if value.len() > 64 {
        return false;
    }
    let parts: Vec<_> = value.split('-').collect();
    let ghsa = |p: &str| p.len() == 4 && class(p, |c| b"23456789cfghjmpqrvwx".contains(&c));
    match parts.as_slice() {
        ["CVE", year, number] => numeric_run(year, 4, 4) && numeric_run(number, 4, 19),
        ["RUSTSEC", year, number] => numeric_run(year, 4, 4) && numeric_run(number, 4, 4),
        ["GHSA", a, b, c] => ghsa(a) && ghsa(b) && ghsa(c),
        _ => false,
    }
}
/// `(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9][A-Za-z0-9_.+:-]*`, at most 128.
fn package(value: &str) -> bool {
    if value.len() > 128 {
        return false;
    }
    let name = match value.strip_prefix('@') {
        Some(scoped) => match scoped.split_once('/') {
            Some((scope, name))
                if !scope.is_empty() && class(scope, |c| alnum(c) || b"_.-".contains(&c)) =>
            {
                name
            }
            _ => return false,
        },
        None => value,
    };
    name.as_bytes().first().copied().is_some_and(alnum)
        && class(name, |c| alnum(c) || b"_.+:-".contains(&c))
}
/// `[a-z0-9./:-]+@sha256:[0-9a-f]{64}`.
fn pinned_image(value: &str) -> bool {
    match value.split_once('@') {
        Some((name, pin)) => {
            !name.is_empty()
                && class(
                    name,
                    |c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'/' | b':' | b'-'),
                )
                && pin
                    .strip_prefix("sha256:")
                    .is_some_and(|hex| hex_lower(hex, 64))
        }
        None => false,
    }
}
/// `re.findall(r'^  - id: ([A-Za-z0-9_.-]{1,128})$', text, re.MULTILINE)`.
pub fn semgrep_rule_ids(text: &str) -> Vec<String> {
    text.split('\n')
        .filter_map(|line| line.strip_prefix("  - id: "))
        .filter(|id| {
            (1..=128).contains(&id.len()) && class(id, |c| alnum(c) || b"_.-".contains(&c))
        })
        .map(str::to_owned)
        .collect()
}
/// The former `relative_path` check for fixture/secret source paths.
fn canonical_relative(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\\')
        && !value.starts_with('/')
        && !value.split('/').any(|part| matches!(part, "" | "." | ".."))
}

fn unique() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{:x}-{:x}-{:x}",
        std::process::id(),
        nanos,
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// A private capture file under the work directory (0600, removed on drop).
struct Temporary {
    path: PathBuf,
    file: File,
}
impl Temporary {
    fn new(work: &Path) -> Result<Self> {
        let path = work.join(format!(".capture-{}", unique()));
        let file = os(OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path))?;
        Ok(Self { path, file })
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub struct Captured {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr_sha256: String,
}

/// `subprocess.run(..., stdout=file, stderr=file, timeout=...)`: on timeout the
/// child is killed and reaped and the run aborts (`TimeoutExpired`).
fn run_bounded(command: &mut Command, work: &Path, timeout: Duration) -> Result<Captured> {
    let out = Temporary::new(work)?;
    let err = Temporary::new(work)?;
    command
        .stdin(Stdio::null())
        .stdout(os(out.file.try_clone())?)
        .stderr(os(err.file.try_clone())?);
    let mut child = os(command.spawn())?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = os(child.try_wait())? {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Fail::Abort("subprocess timed out"));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // Size is judged only after exit, like the former out.tell() check.
    require(
        os(out.file.metadata())?.len() <= REPORT_LIMIT,
        "scanner report exceeds limit",
    )?;
    Ok(Captured {
        code: status
            .code()
            .unwrap_or_else(|| -status.signal().unwrap_or(0)),
        stdout: os(fs::read(&out.path))?,
        stderr_sha256: digest(&err.path)?,
    })
}

/// `subprocess.check_output(['git', '-C', root, *args])` with inherited environment and stderr.
fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = os(Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output())?;
    if !output.status.success() {
        return Err(Fail::Abort("Git command failed"));
    }
    Ok(output.stdout)
}
fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    String::from_utf8(git(root, args)?)
        .map(|s| s.trim().to_owned())
        .map_err(|_| Fail::Refuse("non-UTF-8 Git output"))
}

/// Export Git blobs, ignoring export-ignore/filter attributes and worktree bytes.
pub fn export_source(checkout: &Path, revision: &str, destination: &Path) -> Result<Vec<Value>> {
    require(hex_lower(revision, 40), "immutable source required")?;
    os(fs::create_dir(destination))?;
    let mut rows = Vec::new();
    for record in git(checkout, &["ls-tree", "-rz", revision])?.split(|b| *b == 0) {
        if record.is_empty() {
            continue;
        }
        let tab = record
            .iter()
            .position(|b| *b == b'\t')
            .ok_or(Fail::Refuse("invalid Git tree record"))?;
        let header = std::str::from_utf8(&record[..tab])
            .map_err(|_| Fail::Refuse("invalid Git tree header"))?;
        let path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| Fail::Refuse("non-UTF-8 source path"))?;
        let fields: Vec<_> = header.split_whitespace().collect();
        let [mode, kind, oid] = fields.as_slice() else {
            return Err(Fail::Refuse("invalid Git tree header"));
        };
        require(
            !path.starts_with('/') && !path.split('/').any(|part| part == ".."),
            "invalid source path",
        )?;
        require(
            *kind == "blob" && matches!(*mode, "100644" | "100755" | "120000"),
            "submodules and unknown Git entries need independent source qualification",
        )?;
        let data = git(checkout, &["cat-file", "blob", oid])?;
        let target = destination.join(path);
        if let Some(parent) = target.parent() {
            os(fs::create_dir_all(parent))?;
        }
        // Symlinks become their literal target text; no host file can be followed.
        os(fs::write(&target, &data))?;
        rows.push(json::object([
            ("path", Value::str(path)),
            ("mode", Value::str(*mode)),
            ("sha256", Value::str(sha256::hex(&data))),
        ]));
    }
    require(!rows.is_empty(), "empty source tree")?;
    Ok(rows)
}

fn findings<'a>(row: &'a Value, field: &str) -> Result<&'a [Value]> {
    // `row.get(field) or []`, then it must be a list.
    match row.get(field) {
        Some(value) if value.truthy() => value
            .as_array()
            .ok_or(Fail::Refuse("invalid scanner findings")),
        _ => Ok(&[]),
    }
}
fn results(report: &Value) -> Result<&[Value]> {
    match report.get("Results") {
        None => Ok(&[]),
        Some(value) => value
            .as_array()
            .ok_or(Fail::Refuse("invalid scanner results")),
    }
}

/// Validate scanner completion and count findings, including public fixtures.
pub fn inspect_report(kind: &str, report: &Value) -> Result<usize> {
    require(
        report.as_object().is_some(),
        "scanner report is not an object",
    )?;
    if kind == "sast" {
        let results = report.get("results").and_then(Value::as_array);
        let errors = report.get("errors").and_then(Value::as_array);
        let (Some(results), Some(errors)) = (results, errors) else {
            return Err(Fail::Refuse("invalid SAST report"));
        };
        require(
            errors.is_empty(),
            "SAST had parse, timeout or analysis errors",
        )?;
        let scanned = match report.get("paths") {
            None => None,
            Some(paths) => {
                require(paths.as_object().is_some(), "SAST scanned no files")?;
                paths.get("scanned").and_then(Value::as_array)
            }
        };
        require(
            scanned.is_some_and(|s| !s.is_empty()),
            "SAST scanned no files",
        )?;
        return Ok(results.len());
    }
    require(
        report.get("SchemaVersion").is_some_and(|v| v.equals_int(2)),
        "unsupported vulnerability/secret report",
    )?;
    let field = if kind == "secrets" {
        "Secrets"
    } else {
        "Vulnerabilities"
    };
    let mut count = 0;
    for row in results(report)? {
        require(row.as_object().is_some(), "invalid scanner result")?;
        count += findings(row, field)?.len();
    }
    Ok(count)
}

fn location(value: Option<&Value>, paths: &BTreeSet<String>) -> Option<String> {
    let value = value?.as_str()?;
    let value = value.strip_prefix("/input/").unwrap_or(value);
    (location_pattern(value)
        && paths.contains(value)
        && !value.split('/').any(|p| matches!(p, "" | "." | "..")))
    .then(|| value.to_owned())
}
fn severity(value: Option<&Value>) -> Option<&str> {
    let value = value?.as_str()?;
    matches!(
        value,
        "UNKNOWN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "INFO" | "WARNING" | "ERROR"
    )
    .then_some(value)
}
/// Python `str.strip()` whitespace.
fn python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Project known metadata fields, never messages, snippets, matches or metavars.
///
/// Invalid/oversized optional metadata is omitted, not truncated or stringified.
/// Paths must name exported source files; artifact-only targets are omitted.
pub fn finding_diagnostics(
    kind: &str,
    report: &Value,
    source_paths: &BTreeSet<String>,
    rule_ids: &[String],
) -> Result<Vec<Value>> {
    let mut pairs: Vec<(Option<&Value>, &Value)> = Vec::new();
    match kind {
        "sast" => {
            let results = key(report, "results")?
                .as_array()
                .ok_or(Fail::Refuse("invalid SAST report"))?;
            pairs.extend(results.iter().map(|finding| (None, finding)));
        }
        "dependencies" => {
            for result in results(report)? {
                for finding in findings(result, "Vulnerabilities")? {
                    pairs.push((result.get("Target"), finding));
                }
            }
        }
        _ => return Err(Fail::Refuse("unsupported diagnostic kind")),
    }
    let mut diagnostics = Vec::new();
    for (target, finding) in pairs {
        require(finding.as_object().is_some(), "invalid scanner finding")?;
        if diagnostics.len() == DIAGNOSTIC_LIMIT {
            continue;
        }
        let mut item = Value::Object(Vec::new());
        let (path, level) = if kind == "sast" {
            if let Some(check) = finding
                .get("check_id")
                .and_then(Value::as_str)
                .filter(|s| check_id_pattern(s))
            {
                // Semgrep may prefix IDs with the config path. Emit only the
                // canonical ID from trusted policy, never a report-supplied prefix.
                let rules: Vec<_> = rule_ids
                    .iter()
                    .filter(|rule| {
                        check == rule.as_str()
                            || check
                                .strip_suffix(rule.as_str())
                                .is_some_and(|p| p.ends_with('.'))
                    })
                    .collect();
                if let [rule] = rules.as_slice() {
                    item.set("rule_id", Value::str(rule.as_str()));
                }
            }
            let path = location(finding.get("path"), source_paths);
            // `type(line) is int` (as_int is None for bools, floats and huge ints).
            let line = finding
                .get("start")
                .filter(|s| s.as_object().is_some())
                .and_then(|s| s.get("line"))
                .and_then(Value::as_int)
                .filter(|n| *n > 0 && *n <= 10_000_000);
            if let (Some(_), Some(n)) = (&path, line) {
                item.set("line", Value::int(n));
            }
            let extra = finding.get("extra").filter(|e| e.as_object().is_some());
            (path, extra.and_then(|e| severity(e.get("severity"))))
        } else {
            if let Some(id) = finding
                .get("VulnerabilityID")
                .and_then(Value::as_str)
                .filter(|s| advisory(s))
            {
                item.set("vulnerability_id", Value::str(id));
            }
            if let Some(name) = finding
                .get("PkgName")
                .and_then(Value::as_str)
                .filter(|s| package(s))
            {
                item.set("package", Value::str(name));
            }
            if let Some(installed) = finding
                .get("InstalledVersion")
                .and_then(Value::as_str)
                .filter(|s| version(s))
            {
                item.set("installed_version", Value::str(installed));
            }
            if let Some(fixed) = finding
                .get("FixedVersion")
                .and_then(Value::as_str)
                .filter(|s| s.chars().count() <= 256)
            {
                let versions: Vec<_> = fixed
                    .split(',')
                    .map(|v| v.trim_matches(python_space))
                    .collect();
                if !versions.is_empty()
                    && versions.len() <= 8
                    && versions.iter().all(|v| version(v))
                {
                    item.set(
                        "fixed_versions",
                        Value::Array(versions.into_iter().map(Value::str).collect()),
                    );
                }
            }
            (
                location(target, source_paths),
                severity(finding.get("Severity")),
            )
        };
        if let Some(path) = path {
            item.set("path", Value::str(path));
        }
        if let Some(level) = level {
            item.set("severity", Value::str(level));
        }
        diagnostics.push(item);
    }
    Ok(diagnostics)
}

const FIXTURE_SCHEMA: &str = "busbar.public-secret-fixtures/1";
const FIXTURE_FIELDS: [&str; 9] = [
    "id",
    "repository",
    "path",
    "source_sha256",
    "rule_id",
    "start_line",
    "end_line",
    "reason",
    "provenance",
];

fn policy_entries(data: &[u8]) -> Result<Vec<Value>> {
    let policy = parse(data)?;
    let valid = policy.has_keys(&["schema", "fixtures"])
        && policy.get("schema").and_then(Value::as_str) == Some(FIXTURE_SCHEMA)
        && policy.get("fixtures").and_then(Value::as_array).is_some();
    require(valid, "invalid trusted fixture policy")?;
    let mut entries: Vec<Value> = Vec::new();
    for entry in policy
        .get("fixtures")
        .and_then(Value::as_array)
        .unwrap_or_default()
    {
        let fields_ok = entry.has_keys(&FIXTURE_FIELDS);
        require(fields_ok, "invalid trusted fixture entry")?;
        require(
            entry
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(canonical_relative),
            "noncanonical scanner source path",
        )?;
        let strings = FIXTURE_FIELDS
            .iter()
            .filter(|k| !matches!(**k, "start_line" | "end_line"))
            .all(|k| {
                entry
                    .get(k)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
            });
        let lines = match (entry.get("start_line"), entry.get("end_line")) {
            (Some(Value::Number(start)), Some(Value::Number(end)))
                if entry.at("start_line").is_int() && entry.at("end_line").is_int() =>
            {
                int_cmp(start, "0") == CmpOrdering::Greater
                    && int_cmp(start, end) != CmpOrdering::Greater
            }
            _ => false,
        };
        let id = entry.get("id").and_then(Value::as_str);
        let duplicate = entries
            .iter()
            .any(|e| e.get("id").and_then(Value::as_str) == id);
        require(
            strings
                && entry
                    .get("source_sha256")
                    .and_then(Value::as_str)
                    .is_some_and(|s| hex_lower(s, 64))
                && lines
                && !duplicate,
            "invalid or duplicate trusted fixture entry",
        )?;
        entries.push(entry.clone());
    }
    Ok(entries)
}

/// Compare canonical decimal integers (Python ints are unbounded).
fn int_cmp(a: &str, b: &str) -> CmpOrdering {
    let (an, a) = a.strip_prefix('-').map_or((false, a), |d| (true, d));
    let (bn, b) = b.strip_prefix('-').map_or((false, b), |d| (true, d));
    let magnitude = a.len().cmp(&b.len()).then_with(|| a.cmp(b));
    match (an, bn) {
        (false, false) => magnitude,
        (true, true) => magnitude.reverse(),
        (false, true) => CmpOrdering::Greater,
        (true, false) => CmpOrdering::Less,
    }
}

/// Python `Path.is_symlink()`: missing paths are not links.
fn is_symlink(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => Ok(false),
        Err(_) => Err(Fail::Abort("cannot inspect scanner source")),
    }
}
/// Python `Path.is_file()`.
fn is_file(path: &Path) -> Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => Ok(false),
        Err(_) => Err(Fail::Abort("cannot inspect scanner source")),
    }
}

/// Classify deliberate noncredential fixtures without suppressing scanner findings.
///
/// Every match requires exact committed regular-file bytes, location and rule.
/// The policy bytes come from the immutable trusted checkout; source rows are
/// the controller's Git-blob inventory, never candidate metadata.
pub fn classify(
    report: &Value,
    repository: &str,
    source: &Path,
    source_rows: &[Value],
    policy: &[u8],
) -> Result<Value> {
    let entries = policy_entries(policy)?;
    let inventory: BTreeMap<&str, &Value> = source_rows
        .iter()
        .filter_map(|row| Some((row.get("path")?.as_str()?, row)))
        .collect();
    let mut approved = Vec::new();
    let mut used = BTreeSet::new();
    let mut total = 0usize;
    for result in results(report)? {
        let secrets = findings(result, "Secrets")?;
        if secrets.is_empty() {
            continue;
        }
        let name = result
            .get("Target")
            .and_then(Value::as_str)
            .filter(|n| canonical_relative(n));
        let name = name.ok_or(Fail::Refuse("noncanonical scanner source path"))?;
        let mut path = source.to_path_buf();
        require(!is_symlink(&path)?, "indirect scanner source root")?;
        for part in name.split('/') {
            path.push(part);
            require(!is_symlink(&path)?, "indirect scanner source path")?;
        }
        let row = inventory.get(name);
        let regular = row.is_some_and(|row| {
            matches!(
                row.get("mode").and_then(Value::as_str),
                Some("100644" | "100755")
            )
        });
        require(
            regular && is_file(&path)?,
            "scanner source is not a committed regular file",
        )?;
        let file_sha256 = sha256::hex(&os(fs::read(&path))?);
        require(
            row.and_then(|r| r.get("sha256")).and_then(Value::as_str) == Some(file_sha256.as_str()),
            "scanner source changed after export",
        )?;
        for finding in secrets {
            let index = total;
            total += 1;
            require(finding.as_object().is_some(), "invalid scanner finding")?;
            let (start, end) = (finding.get("StartLine"), finding.get("EndLine"));
            let matching: Vec<&Value> = entries
                .iter()
                .filter(|entry| {
                    entry.get("repository").and_then(Value::as_str) == Some(repository)
                        && entry.get("path").and_then(Value::as_str) == Some(name)
                        && entry.get("source_sha256").and_then(Value::as_str)
                            == Some(file_sha256.as_str())
                        && finding
                            .get("RuleID")
                            .is_some_and(|rule| entry.get("rule_id") == Some(rule))
                        && start.is_some_and(Value::is_int)
                        && end.is_some_and(Value::is_int)
                        && entry.get("start_line") == start
                        && entry.get("end_line") == end
                })
                .collect();
            if let [entry] = matching.as_slice() {
                let id = entry
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if used.insert(id) {
                    let mut approval = (*entry).clone();
                    approval.set("finding_index", Value::int(index as i128));
                    approved.push(approval);
                }
            }
        }
    }
    Ok(json::object([
        (
            "classification_policy_sha256",
            Value::str(sha256::hex(policy)),
        ),
        (
            "classified_public_fixtures",
            Value::int(approved.len() as i128),
        ),
        (
            "unresolved_findings",
            Value::int((total - approved.len()) as i128),
        ),
        ("public_fixture_classifications", Value::Array(approved)),
    ]))
}

/// `dt.timedelta(hours=value)` in microseconds; None where Python raises.
fn hours_micros(value: &Value) -> Option<i128> {
    const LIMIT_DAYS: i128 = 999_999_999;
    let micros = match value {
        Value::Bool(b) => i128::from(*b) * 3_600_000_000,
        Value::Number(_) if value.is_int() => value.as_int()?.checked_mul(3_600_000_000)?,
        Value::Number(_) => {
            let f = value.as_float().filter(|f| f.is_finite())?;
            (f * 3.6e9).round_ties_even() as i128
        }
        _ => return None,
    };
    (micros.div_euclid(86_400_000_000) <= LIMIT_DAYS
        && micros.div_euclid(86_400_000_000) >= -LIMIT_DAYS)
        .then_some(micros)
}

pub fn now_micros() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i128)
        .unwrap_or_default()
}

pub fn database_identity(cache: &Path, max_age: &Value, now: i128) -> Result<Value> {
    let metadata_path = cache.join("db/metadata.json");
    let metadata = read_text_json(&metadata_path)?;
    let updated_text = key_str(&metadata, "UpdatedAt")?;
    let updated =
        aware_utc_micros(updated_text).ok_or(Fail::Refuse("invalid database timestamp"))?;
    let age = now - updated;
    let fresh = age >= 0 && hours_micros(max_age).is_some_and(|limit| age <= limit);
    require(fresh, "vulnerability database is stale or future-dated")?;
    Ok(json::object([
        ("updated_at", Value::str(updated_text)),
        ("sha256", Value::str(digest(&cache.join("db/trivy.db"))?)),
        ("metadata_sha256", Value::str(digest(&metadata_path)?)),
    ]))
}

unsafe extern "C" {
    fn getuid() -> u32;
    fn getgid() -> u32;
}

pub struct Scanner {
    pub policy: PathBuf,
    work: PathBuf,
    tools: Value,
    home: PathBuf,
    path_env: std::ffi::OsString,
    pub docker_host: String,
    cache: PathBuf,
    pub steps: Vec<Value>,
    pub repository: String,
    pub source_rows: Vec<Value>,
}

impl Scanner {
    pub fn new(trusted: &Path, work: &Path) -> Result<Self> {
        let policy = trusted.join("ci/security");
        let tools = read_text_json(&policy.join("tools.json"))?;
        for name in ["trivy", "semgrep"] {
            require(
                key_str(&tools, name).is_ok_and(pinned_image),
                "scanner image must be digest pinned",
            )?;
        }
        let home = work.join("scanner-home");
        os(fs::create_dir(&home))?;
        // Do not inherit registry/cloud credentials, plugins, candidate config or CI tokens.
        let path_env = std::env::var_os("PATH").ok_or(Fail::Refuse("PATH is required"))?;
        let cache = work.join("database");
        os(fs::create_dir(&cache))?;
        Ok(Self {
            policy,
            work: work.to_owned(),
            tools,
            home,
            path_env,
            docker_host: "unix:///var/run/docker.sock".into(),
            cache,
            steps: Vec::new(),
            repository: String::new(),
            source_rows: Vec::new(),
        })
    }

    fn image(&self, tool: &str) -> Result<&str> {
        key_str(&self.tools, tool)
    }

    fn docker(&self) -> Command {
        let mut command = Command::new("docker");
        command
            .env_clear()
            .env("PATH", &self.path_env)
            .env("HOME", &self.home)
            .env("DOCKER_CONFIG", &self.home)
            .args(["--host", &self.docker_host]);
        command
    }

    pub fn container_command(
        &self,
        name: &str,
        tool: &str,
        argv: &[String],
        mounts: &[(&Path, &str, bool)],
        network: &str,
    ) -> Result<Command> {
        let mut command = self.docker();
        // SAFETY: getuid/getgid have no preconditions and cannot fail.
        let user = unsafe { format!("{}:{}", getuid(), getgid()) };
        command
            .args([
                "run",
                "--rm",
                "--name",
                name,
                "--pull=never",
                "--read-only",
                "--cap-drop=ALL",
            ])
            .args([
                "--security-opt=no-new-privileges",
                &format!("--network={network}"),
            ])
            .args([
                "--pids-limit=256",
                "--memory=3g",
                "--cpus=2",
                "--user",
                &user,
            ])
            .args([
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=512m,mode=1777",
                "-e",
                "HOME=/tmp",
            ])
            .args(["--workdir", "/tmp", "--entrypoint", tool]);
        for (source, target, writable) in mounts {
            let source = source
                .to_str()
                .ok_or(Fail::Refuse("invalid mount source"))?;
            require(!source.contains(','), "comma in mount source")?;
            let spec = format!(
                "type=bind,src={source},dst={target}{}",
                if *writable { "" } else { ",readonly" }
            );
            command.args(["--mount", &spec]);
        }
        command.arg(self.image(tool)?).args(argv);
        Ok(command)
    }

    /// Reports may contain secrets; never stream them to job logs.
    pub fn container(
        &self,
        tool: &str,
        argv: &[String],
        mounts: &[(&Path, &str, bool)],
        network: &str,
    ) -> Result<Captured> {
        let name = format!("busbar-scan-{}", unique());
        let mut command = self.container_command(&name, tool, argv, mounts, network)?;
        let result = run_bounded(&mut command, &self.work, Duration::from_secs(1200));
        // Always remove a possibly surviving container; a cleanup failure wins.
        let mut remove = self.docker();
        remove.args(["rm", "-f", &name]);
        run_bounded(&mut remove, &self.work, Duration::from_secs(30))?;
        result
    }

    fn prepare_image(&self, tool: &str) -> Result<()> {
        // Local immutable references are usable without any registry contact.
        // Policy selects Google's existing Hub mirror; never retry anonymous Hub.
        let image = self.image(tool)?;
        let inspect = || {
            let mut command = self.docker();
            command.args([
                "image",
                "inspect",
                "--format",
                "{{json .RepoDigests}}",
                image,
            ]);
            run_unbounded_output(&mut command, &self.work, Duration::from_secs(30))
        };
        let mut result = inspect()?;
        if result.code != 0 {
            let mut pull = self.docker();
            pull.args(["pull", image]);
            let pulled = run_unbounded_output(&mut pull, &self.work, Duration::from_secs(600))?;
            if pulled.code != 0 {
                return Err(Fail::Abort("pinned scanner image pull failed"));
            }
            result = inspect()?;
        }
        require(result.code == 0, "pinned scanner image unavailable")?;
        let references = parse(&result.stdout)?;
        let expected = image
            .split_once('@')
            .map(|(_, pin)| pin)
            .unwrap_or_default();
        let found = references.as_array().is_some_and(|refs| {
            refs.iter().any(|r| {
                r.as_str()
                    .is_some_and(|r| r.rsplit('@').next() == Some(expected))
            })
        });
        require(found, "scanner image digest differs from policy")
    }

    pub fn prepare(&self) -> Result<Value> {
        for tool in ["trivy", "semgrep"] {
            self.prepare_image(tool)?;
        }
        // Only this source-free container has network access. Scan containers cannot
        // contact registries, SaaS scanners, secret validation APIs or package servers.
        let args = strings(&[
            "image",
            "--download-db-only",
            "--disable-telemetry",
            "--skip-version-check",
            "--cache-dir",
            "/cache",
        ]);
        let result = self.container("trivy", &args, &[(&self.cache, "/cache", true)], "bridge")?;
        require(result.code == 0, "vulnerability database download failed")?;
        database_identity(
            &self.cache,
            key(&self.tools, "database_max_age_hours")?,
            now_micros(),
        )
    }

    pub fn trivy(&self, mode: &str, scanners: &str, extra: &[&str]) -> Vec<String> {
        let mut args = strings(&[
            mode,
            "--config",
            "/policy/trivy.yaml",
            "--ignorefile",
            "/policy/trivy.ignore",
        ]);
        if mode != "sbom" {
            args.extend(strings(&["--secret-config", "/policy/trivy-secret.yaml"]));
        }
        args.extend(strings(&[
            "--disable-telemetry",
            "--skip-version-check",
            "--cache-dir",
            "/cache",
            "--cache-backend",
            "memory",
            "--skip-db-update",
            "--skip-java-db-update",
            "--offline-scan",
            "--scanners",
            scanners,
            "--severity",
            if scanners == "vuln" {
                "HIGH,CRITICAL"
            } else {
                "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
            },
        ]));
        args.extend(strings(extra));
        args
    }

    pub fn scan(&mut self, name: &str, source: &Path, argv: &[String], tool: &str) -> Result<()> {
        let mounts = [
            (source, "/input", false),
            (self.policy.as_path(), "/policy", false),
            (self.cache.as_path(), "/cache", false),
        ];
        let captured = self.container(tool, argv, &mounts, "none")?;
        let mut row = json::object([
            ("name", Value::str(name)),
            ("tool_image", Value::str(self.image(tool)?)),
            ("exit_code", Value::int(captured.code)),
            ("status", Value::str("fail")),
            ("report_sha256", Value::str(sha256::hex(&captured.stdout))),
            ("stderr_sha256", Value::str(captured.stderr_sha256.as_str())),
        ]);
        let outcome = self.assess(name, source, &captured.stdout, captured.code, &mut row);
        if outcome.is_ok() {
            row.set("status", Value::str("pass"));
        }
        self.steps.push(row);
        match outcome {
            Ok(()) => Ok(()),
            Err(Fail::Refuse(_)) => Err(Fail::Refuse("security scan refused")),
            Err(abort) => Err(abort),
        }
    }

    fn assess(
        &self,
        kind: &str,
        source: &Path,
        data: &[u8],
        code: i32,
        row: &mut Value,
    ) -> Result<()> {
        let report = parse(data)?;
        let count = inspect_report(kind, &report)?;
        row.set("findings", Value::int(count as i128)); // Raw count, including classified public fixtures.
        if matches!(kind, "dependencies" | "sast") {
            // This first-party policy uses one plain ID per line. Unknown or
            // differently formatted IDs are safely omitted from diagnostics.
            let rule_ids = if kind == "sast" {
                semgrep_rule_ids(&read_text(&self.policy.join("semgrep.yaml"))?)
            } else {
                Vec::new()
            };
            let paths: BTreeSet<String> = self
                .source_rows
                .iter()
                .filter_map(|r| r.get("path")?.as_str().map(str::to_owned))
                .collect();
            let diagnostics = finding_diagnostics(kind, &report, &paths, &rule_ids)?;
            row.set(
                "diagnostics_omitted",
                Value::int((count - diagnostics.len()) as i128),
            );
            row.set("diagnostics", Value::Array(diagnostics));
        }
        if kind == "secrets" {
            let private = self.work.join("private-scanner-reports");
            match fs::DirBuilder::new().mode(0o700).create(&private) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::AlreadyExists && private.is_dir() => {}
                Err(_) => return Err(Fail::Abort("private scanner output unavailable")),
            }
            require(!is_symlink(&private)?, "indirect private scanner output")?;
            os(fs::set_permissions(
                &private,
                fs::Permissions::from_mode(0o700),
            ))?;
            let path = private.join(format!("secrets-{}.json", unique()));
            let mut file = os(OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path))?;
            os(file.write_all(data))?;
        }
        if kind == "secrets" && count > 0 && !self.repository.is_empty() {
            let policy = os(fs::read(self.policy.join("public-secret-fixtures.json")))?;
            let classification = classify(
                &report,
                &self.repository,
                source,
                &self.source_rows,
                &policy,
            )?;
            for (name, value) in classification.as_object().into_iter().flatten() {
                row.set(name, value.clone());
            }
            let unresolved = row
                .get("unresolved_findings")
                .is_some_and(|v| v.equals_int(0));
            require(
                code == 1 && unresolved,
                "unresolved secrets or scanner execution failure",
            )
        } else {
            require(
                code == 0 && count == 0,
                "scanner findings or execution failure",
            )
        }
    }
}

/// `subprocess.run(..., capture_output=True, timeout=...)` (no report bound).
fn run_unbounded_output(command: &mut Command, work: &Path, timeout: Duration) -> Result<Captured> {
    let out = Temporary::new(work)?;
    command
        .stdin(Stdio::null())
        .stdout(os(out.file.try_clone())?)
        .stderr(Stdio::null());
    let mut child = os(command.spawn())?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = os(child.try_wait())? {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Fail::Abort("subprocess timed out"));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Ok(Captured {
        code: status
            .code()
            .unwrap_or_else(|| -status.signal().unwrap_or(0)),
        stdout: os(fs::read(&out.path))?,
        stderr_sha256: String::new(),
    })
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}

fn environment(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| Fail::Refuse("missing CI environment"))
}

/// Candidate `.semgrepignore` controls (files, or directories, which fail like
/// `Path.write_text` on a directory) are emptied, then the root one is written.
fn neutralize_semgrepignore(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in os(fs::read_dir(&directory))? {
            let entry = os(entry)?;
            let kind = os(entry.file_type())?;
            if entry.file_name() == ".semgrepignore" {
                os(fs::write(entry.path(), b""))?;
            }
            if kind.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    os(fs::write(root.join(".semgrepignore"), b""))
}

pub fn run_source(trusted: &Path, checkout: &Path, work: &Path, output: &Path) -> Result<Value> {
    require(
        std::env::var("CI_JOB_NAME").ok().as_deref() == Some("security-scans"),
        "dedicated security-scans CI job required",
    )?;
    require(
        std::env::var("GITLAB_CI").ok().as_deref() == Some("true"),
        "security qualification runs in GitLab",
    )?;
    let source = environment("CI_COMMIT_SHA")?;
    let policy = git_text(trusted, &["rev-parse", "HEAD"])?;
    let mut receipt = json::object([
        ("schema", Value::str("busbar.security-scans/1")),
        ("status", Value::str("fail")),
        ("repository", Value::str(environment("CI_PROJECT_PATH")?)),
        ("source", Value::str(source.as_str())),
        ("policy_revision", Value::str(policy)),
        ("pipeline_id", Value::str(environment("CI_PIPELINE_ID")?)),
        ("job_id", Value::str(environment("CI_JOB_ID")?)),
        ("steps", Value::Array(Vec::new())),
    ]);
    let mut scanner: Option<Scanner> = None;
    let outcome = (|| -> Result<()> {
        let snapshot = work.join("scan-source");
        let rows = export_source(checkout, &source, &snapshot)?;
        receipt.set(
            "source_files_sha256",
            Value::str(sha256::hex(&json::encoded(&Value::Array(rows.clone())))),
        );
        receipt.set(
            "source_tree",
            Value::str(git_text(
                checkout,
                &["rev-parse", &format!("{source}^{{tree}}")],
            )?),
        );
        let scanner = scanner.insert(Scanner::new(trusted, work)?);
        scanner.repository = environment("CI_PROJECT_PATH")?;
        scanner.source_rows = rows;
        let mut files = BTreeMap::new();
        for entry in os(fs::read_dir(&scanner.policy))? {
            let path = os(entry)?.path();
            if is_file(&path)? {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or(Fail::Refuse("invalid policy file name"))?;
                files.insert(name.to_owned(), Value::str(digest(&path)?));
            }
        }
        receipt.set("policy_files", Value::Object(files.into_iter().collect()));
        receipt.set("database", scanner.prepare()?);
        let mut failed = false;
        for (name, scanners) in [("secrets", "secret"), ("dependencies", "vuln")] {
            let args = scanner.trivy("filesystem", scanners, &["/input"]);
            match scanner.scan(name, &snapshot, &args, "trivy") {
                Ok(()) => {}
                Err(Fail::Refuse(_)) => failed = true,
                Err(abort) => return Err(abort),
            }
        }
        // Root and nested candidate ignore files cannot weaken SAST. Secrets were
        // scanned before these control-only files are replaced; no source code changes.
        neutralize_semgrepignore(&snapshot)?;
        let args = strings(&[
            "scan",
            "--config",
            "/policy/semgrep.yaml",
            "--json",
            "--error",
            "--strict",
            "--metrics=off",
            "--disable-version-check",
            "--disable-nosem",
            "--no-git-ignore",
            "--max-target-bytes=0",
            "--optimizations=none",
            "--oss-only",
            "--jobs=2",
            "/input",
        ]);
        match scanner.scan("sast", &snapshot, &args, "semgrep") {
            Ok(()) => {}
            Err(Fail::Refuse(_)) => failed = true,
            Err(abort) => return Err(abort),
        }
        require(!failed, "security scans refused")?;
        receipt.set("status", Value::str("pass"));
        Ok(())
    })();
    if let Some(scanner) = &scanner {
        receipt.set("steps", Value::Array(scanner.steps.clone()));
    }
    if let Some(parent) = output.parent() {
        os(fs::create_dir_all(parent))?;
    }
    os(fs::write(output, json::encoded(&receipt)))?;
    outcome.map(|()| receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary() -> PathBuf {
        let path = std::env::temp_dir().join(format!("busbar-ci-test-{}", unique()));
        fs::create_dir(&path).unwrap();
        path.canonicalize().unwrap()
    }

    #[test]
    fn patterns_match_former_regexes() {
        assert!(
            advisory("CVE-2026-1234")
                && advisory("RUSTSEC-2026-0001")
                && advisory("GHSA-2345-6789-cfgh")
        );
        assert!(
            !advisory("CVE-2026-123")
                && !advisory("GHSA-2345-6789-abcd")
                && !advisory(&format!("CVE-2026-{}", "1".repeat(20)))
        );
        assert!(
            package("@scope/name:1+x")
                && package("a")
                && !package("@/x")
                && !package("@scope")
                && !package("-a")
                && !package("a/b")
        );
        assert!(version("1.2.3-rc1~x") && !version("v1") && !version(&"1".repeat(65)));
        assert!(pinned_image(&format!(
            "mirror.gcr.io/x/y:1.0@sha256:{}",
            "a".repeat(64)
        )));
        assert!(
            !pinned_image(&format!("X@sha256:{}", "a".repeat(64))) && !pinned_image("x:latest")
        );
        assert_eq!(
            semgrep_rule_ids("rules:\n  - id: a.b\n  - id: bad id\n  - id: c\r\n   - id: d\n"),
            ["a.b"]
        );
    }

    #[test]
    fn stale_future_and_naive_databases_refuse() {
        let root = temporary();
        fs::create_dir(root.join("db")).unwrap();
        fs::write(root.join("db/trivy.db"), b"fixture database").unwrap();
        let now = aware_utc_micros("2026-11-10T00:00:00+00:00").unwrap();
        for stamp in [
            "2026-11-10T01:00:00Z",
            "2026-11-06T23:59:59Z",
            "2026-11-10T00:00:00",
        ] {
            fs::write(
                root.join("db/metadata.json"),
                format!("{{\"UpdatedAt\":\"{stamp}\"}}"),
            )
            .unwrap();
            assert!(
                database_identity(&root, &Value::int(72), now).is_err(),
                "{stamp}"
            );
        }
        fs::write(
            root.join("db/metadata.json"),
            "{\"UpdatedAt\":\"2026-11-07T00:00:00Z\"}",
        )
        .unwrap();
        let identity = database_identity(&root, &Value::int(72), now).unwrap();
        assert_eq!(
            identity.get("sha256").and_then(Value::as_str),
            Some(sha256::hex(b"fixture database").as_str())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn containers_are_offline_readonly_and_credential_free() {
        let root = temporary();
        let trusted = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let scanner = Scanner::new(&trusted, &root).unwrap();
        let command = scanner
            .container_command(
                "n",
                "trivy",
                &[],
                &[
                    (&root, "/input", false),
                    (&scanner.policy, "/policy", false),
                ],
                "none",
            )
            .unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for option in [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pull=never",
        ] {
            assert!(args.iter().any(|a| a == option), "{option}");
        }
        assert!(
            args.iter()
                .enumerate()
                .all(|(i, a)| a != "--mount" || args[i + 1].ends_with(",readonly"))
        );
        let envs: Vec<_> = command
            .get_envs()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(envs.len(), 3, "{envs:?}");
        assert!(
            !args[args.iter().position(|a| a == "run").unwrap()..]
                .iter()
                .any(|a| a.contains("docker.sock"))
        );
        let comma = root.join("a,b");
        assert_eq!(
            scanner
                .container_command("n", "trivy", &[], &[(&comma, "/input", false)], "none")
                .err(),
            Some(Fail::Refuse("comma in mount source"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn timeout_aborts_and_oversize_refuses() {
        let root = temporary();
        let mut sleep = Command::new("sleep");
        sleep.arg("5");
        assert_eq!(
            run_bounded(&mut sleep, &root, Duration::from_millis(100)).err(),
            Some(Fail::Abort("subprocess timed out"))
        );
        let mut signal = Command::new("sh");
        signal.args(["-c", "kill -9 $$"]);
        assert_eq!(
            run_bounded(&mut signal, &root, Duration::from_secs(5))
                .unwrap()
                .code,
            -9
        );
        assert_eq!(
            fs::read_dir(&root).unwrap().count(),
            0,
            "captures are removed"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn semgrepignore_directories_abort() {
        let root = temporary();
        fs::create_dir_all(root.join("a/.semgrepignore")).unwrap();
        assert!(matches!(
            neutralize_semgrepignore(&root),
            Err(Fail::Abort(_))
        ));
        fs::remove_dir_all(root.join("a")).unwrap();
        fs::create_dir_all(root.join("b")).unwrap();
        fs::write(root.join("b/.semgrepignore"), b"*\n").unwrap();
        neutralize_semgrepignore(&root).unwrap();
        assert!(fs::read(root.join("b/.semgrepignore")).unwrap().is_empty());
        assert!(fs::read(root.join(".semgrepignore")).unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
