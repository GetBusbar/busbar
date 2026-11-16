// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The judge, obtained and held to its digest: what `bin/oracle` used to do in shell (BLD-6: the
//! launcher is twenty lines, build and CI tooling is Rust). Nothing here judges a cell; this finds
//! the pinned `busbar-oracle` engine, proves it is the pinned one, and says what a run may read.
//!
//! - the CI markers and the token rules: a CI run reads no token (`ci_run`, `release_token`);
//! - the pin, from the branch file's env only (`env_judge_pin`);
//! - the fetched judge: sha256 against the pin, `.sha256` and `.sig` beside it, cached by digest and
//!   environment (`fetch_judge`, `verify_judge_sig`);
//! - the engine clone, which stores no credential (`clone_engine`, `assert_no_token`);
//! - the 1.5.5 golden, read from the object database under ModernCI (`odb_golden`);
//! - which binary is the judge (`resolve_bin`).
//!
//! The tools it drives are the ones the shell drove: `git`, `curl`, `openssl`, `tar`, `sha256sum`.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use regex::Regex;

use crate::oracle::Node;

/// A refusal: what to say on stderr (nothing when empty) and the exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fail {
    pub(crate) code: u8,
    pub(crate) message: String,
}

impl Fail {
    pub(crate) fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// The environment variable `name`, `""` when unset.
pub(crate) fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// The markers of a CI run: a ModernCI marker, the judge path ModernCI hands over, or a bare `CI`.
const CI_MARKERS: [&str; 7] = [
    "BUSBAR_ORACLE_JUDGE_PATH",
    "MODERNCI",
    "MODERNCI_JOB",
    "MODERNCI_TO_SHA",
    "MODERNCI_HEAD",
    "MODERNCI_COMMIT",
    "CI",
];

/// Any CI run: a ModernCI marker or a generic `CI=`. No CI run takes `BUSBAR_ORACLE_RUST_BIN`, and
/// none reads a token.
pub(crate) fn ci_run() -> bool {
    CI_MARKERS.iter().any(|name| !var(name).is_empty())
}

/// A run under ModernCI (`BUSBAR_ORACLE_JUDGE_PATH` is a ModernCI marker too).
pub(crate) fn under_modernci() -> bool {
    CI_MARKERS[..6].iter().any(|name| !var(name).is_empty())
}

/// The token a LOCAL run may use (`BUSBAR_RELEASE_TOKEN`, else `GH_TOKEN`, else `GITHUB_TOKEN`); in
/// a CI run nothing.
pub(crate) fn release_token() -> Option<String> {
    if ci_run() {
        return None;
    }
    ["BUSBAR_RELEASE_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]
        .iter()
        .map(|name| var(name))
        .find(|token| !token.is_empty())
}

/// Which token the release API is read with, never its value.
pub(crate) fn token_word() -> String {
    if ci_run() {
        return String::from(
            "a CI run reads no token (BUSBAR_RELEASE_TOKEN, GH_TOKEN and GITHUB_TOKEN are never read)",
        );
    }
    if !var("BUSBAR_RELEASE_TOKEN").is_empty() {
        String::from("BUSBAR_RELEASE_TOKEN present")
    } else if !var("GH_TOKEN").is_empty() {
        String::from("BUSBAR_RELEASE_TOKEN absent, GH_TOKEN present")
    } else if !var("GITHUB_TOKEN").is_empty() {
        String::from("BUSBAR_RELEASE_TOKEN absent, GITHUB_TOKEN present")
    } else {
        String::from("no token (BUSBAR_RELEASE_TOKEN, GH_TOKEN and GITHUB_TOKEN are all absent)")
    }
}

// ---- small tools ---------------------------------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh directory `<base>/<prefix>XXXXXX`, removed when dropped.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(base: &Path, prefix: &str) -> std::io::Result<Self> {
        std::fs::create_dir_all(base)?;
        loop {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.subsec_nanos());
            let count = COUNTER.fetch_add(1, Ordering::Relaxed);
            let suffix = u64::from(nanos)
                .wrapping_mul(31)
                .wrapping_add(u64::from(std::process::id()) << 20)
                .wrapping_add(count)
                % 0x00ff_ffff_ffff;
            let dir = base.join(format!("{prefix}{suffix:010x}"));
            match std::fs::create_dir(&dir) {
                Ok(()) => return Ok(Self(dir)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// Keep the directory: the caller owns it from here.
    pub(crate) fn keep(self) -> PathBuf {
        let path = self.0.clone();
        std::mem::forget(self);
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The temp base: `$TMPDIR`, else `/tmp`.
pub(crate) fn temp_base() -> PathBuf {
    let base = var("TMPDIR");
    PathBuf::from(if base.is_empty() { "/tmp" } else { &base })
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64, padded.
pub(crate) fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (index, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if index <= chunk.len() {
                out.push(char::from(B64[((n >> shift) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Standard base64, whitespace ignored; `None` for anything else.
pub(crate) fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut bits = 0u32;
    let mut count = 0u32;
    let mut padding = 0usize;
    for c in text.chars().filter(|c| !c.is_whitespace()) {
        if c == '=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            return None;
        }
        let value = B64.iter().position(|&b| char::from(b) == c)?;
        bits = (bits << 6) | u32::try_from(value).ok()?;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// The hex sha256 of a file (`sha256sum`, else `shasum -a 256`), or nothing.
pub(crate) fn sha256_of(path: &Path) -> Option<String> {
    let attempt = |program: &str, first: &[&str]| -> Option<String> {
        let output = Command::new(program)
            .args(first)
            .arg("--")
            .arg(path)
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let digest: String = String::from_utf8_lossy(&output.stdout)
            .chars()
            .take(64)
            .collect();
        (digest.len() == 64).then_some(digest)
    };
    attempt("sha256sum", &[]).or_else(|| attempt("shasum", &["-a", "256"]))
}

/// `uname <flag>`, trimmed (through the PATH, as the shell asked it).
fn uname(flag: &str) -> String {
    Command::new("uname")
        .arg(flag)
        .stderr(Stdio::null())
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// This host's architecture as the pin spells it (`uname -m`, `arm64` as `aarch64`).
pub(crate) fn judge_arch() -> String {
    let arch = uname("-m");
    if arch == "arm64" {
        String::from("aarch64")
    } else {
        arch
    }
}

/// `uname -s`, lower case.
pub(crate) fn host_os() -> String {
    uname("-s").to_lowercase()
}

/// The C library word of the judge cache's key: `muslN`, `glibc<major.minor>`, or
/// `ORACLE_JUDGE_LIBC` (the selftest's plant).
fn judge_libc() -> String {
    let planted = var("ORACLE_JUDGE_LIBC");
    if !planted.is_empty() {
        return planted;
    }
    let text = Command::new("ldd")
        .arg("--version")
        .output()
        .map(|output| {
            let mut all = String::from_utf8_lossy(&output.stdout).into_owned();
            all.push_str(&String::from_utf8_lossy(&output.stderr));
            all
        })
        .unwrap_or_default();
    let first = text.lines().next().unwrap_or_default();
    if first.contains("musl") {
        return String::from("musl");
    }
    let version = Regex::new(r"[0-9]+\.[0-9]+$")
        .ok()
        .and_then(|pattern| pattern.find(first).map(|found| found.as_str().to_owned()));
    format!("glibc{}", version.as_deref().unwrap_or("unknown"))
}

/// The environment a cached judge was fetched on, and the only one it is reused on: the OS, the
/// architecture and the C library (a GLIBC_2.39 binary from one environment refused to start on
/// another, ModernCI #1827).
pub(crate) fn judge_env() -> String {
    format!("{}-{}-{}", host_os(), judge_arch(), judge_libc())
}

/// The judge runs here: its `--help` answers (a binary that cannot start on this host is no judge).
pub(crate) fn judge_starts(bin: &Path) -> bool {
    Command::new(bin)
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// A file's mode says it can run.
pub(crate) fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Mark a file executable.
pub(crate) fn make_executable(path: &Path) -> std::io::Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(permissions.mode() | 0o755);
    std::fs::set_permissions(path, permissions)
}

/// The value of `key=value` in a pin text (the first such line).
pub(crate) fn pin_in(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once('=')?;
            (name == key).then(|| value.to_owned())
        })
        .unwrap_or_default()
}

/// `text` is exactly `len` lower-case hex digits.
fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

// ---- the token is used, never stored ------------------------------------------------------------

/// `git`, authenticated for github.com when a LOCAL run has a token: a one-shot
/// `http.<github>.extraheader` through git's environment config (never a URL, never an argv, never
/// the checkout's `.git/config`).
pub(crate) fn git_with_token() -> Command {
    let mut git = Command::new("git");
    if let Some(token) = release_token() {
        let encoded = base64_encode(format!("x-access-token:{token}").as_bytes());
        git.env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "http.https://github.com/.extraheader")
            .env(
                "GIT_CONFIG_VALUE_0",
                format!("AUTHORIZATION: basic {encoded}"),
            );
    }
    git
}

/// Refuse when a credential persisted in the checkout's git config.
pub(crate) fn assert_no_token(checkout: &Path) -> Result<(), Fail> {
    let config = checkout.join(".git").join("config");
    let Ok(text) = std::fs::read_to_string(&config) else {
        return Ok(());
    };
    let shape = Regex::new(r"(?i)x-access-token|extraheader|://[^/@\s]+@").map_err(|error| {
        Fail::new(
            1,
            format!("oracle: the credential pattern did not compile: {error}"),
        )
    })?;
    let token = release_token().unwrap_or_default();
    if shape.is_match(&text) || (!token.is_empty() && text.contains(&token)) {
        return Err(Fail::new(
            1,
            format!(
                "oracle: a credential persisted in {}; refusing (the engine clone must never store a token)",
                config.display()
            ),
        ));
    }
    Ok(())
}

/// A git step whose stdout goes to our stderr; its status.
fn git_step(mut git: Command, quiet: bool) -> bool {
    git.stdin(Stdio::null())
        .stdout(Stdio::from(std::io::stderr()));
    if quiet {
        git.stderr(Stdio::null());
    }
    git.status().is_ok_and(|status| status.success())
}

/// The pinned busbar-release ref, checked out at `checkout`, no token stored.
pub(crate) fn clone_engine(repo: &str, rref: &str, checkout: &Path) -> Result<(), Fail> {
    let dir = checkout.to_string_lossy().into_owned();
    if checkout.join(".git").is_dir() {
        let mut set_url = Command::new("git");
        set_url
            .args(["-C", &dir, "remote", "set-url", "origin", repo])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _ = set_url.status();
    } else {
        let mut clone = git_with_token();
        clone.args(["clone", "--no-checkout", repo, &dir]);
        if !git_step(clone, false) {
            return Err(Fail::new(1, ""));
        }
    }
    // A checkout that already holds the pinned commit needs no network: a runner without a token
    // cannot fetch, though the staged engine checkout is complete.
    let holds = Command::new("git")
        .args(["-C", &dir, "cat-file", "-e", &format!("{rref}^{{commit}}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !holds {
        let mut shallow = git_with_token();
        shallow.args(["-C", &dir, "fetch", "--depth", "1", "origin", rref]);
        if !git_step(shallow, true) {
            let mut full = git_with_token();
            full.args(["-C", &dir, "fetch", "origin"]);
            if !git_step(full, false) {
                return Err(Fail::new(1, ""));
            }
        }
    }
    assert_no_token(checkout)?;
    let mut checkout_ref = Command::new("git");
    checkout_ref.args(["-C", &dir, "checkout", "--force", rref]);
    if git_step(checkout_ref, false) {
        Ok(())
    } else {
        Err(Fail::new(1, ""))
    }
}

// ---- the release API -----------------------------------------------------------------------------

/// An authenticated GET of the release API; the token reaches curl on stdin as a config line, never
/// on an argv. The body is returned, or written to `out` (and an empty body returned).
pub(crate) fn release_api(
    url: &str,
    accept: &str,
    out: Option<&Path>,
    what: &str,
) -> Result<Vec<u8>, String> {
    if ci_run() {
        return Err(format!(
            "oracle: NO JUDGE: a CI run never reads busbar-release's dev-bin release: the judge is \
             ModernCI's $BUSBAR_ORACLE_JUDGE_PATH, fetched outside the run from its tool pin ({})",
            token_word()
        ));
    }
    let Some(token) = release_token() else {
        return Err(format!(
            "oracle: no token to read busbar-release's dev-bin release ({})",
            token_word()
        ));
    };
    let scratch = TempDir::new(&temp_base(), "busbar-oracle-api.")
        .map_err(|error| format!("oracle: cannot make a scratch dir: {error}"))?;
    let body = scratch.path().join("body");
    let mut curl = Command::new("curl");
    curl.args(["-sSL", "--retry", "3", "-K", "-", "-H"])
        .arg(format!("Accept: {accept}"))
        .arg("-o")
        .arg(&body)
        .args(["-w", "%{http_code}"])
        .arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = curl
        .spawn()
        .map_err(|error| format!("oracle: cannot run curl: {error}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(format!("header = \"Authorization: Bearer {token}\"\n").as_bytes());
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("oracle: curl failed: {error}"))?;
    let code = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let code = if code.is_empty() {
        String::from("000")
    } else {
        code
    };
    if code != "200" {
        let word = token_word();
        return Err(match code.as_str() {
            "403" => format!(
                "oracle: busbar-release answered 403 (forbidden) for {what}: the token cannot read it ({word})"
            ),
            "404" => format!(
                "oracle: busbar-release answered 404 (not found) for {what}: not published, or the token cannot see it ({word})"
            ),
            _ => format!("oracle: busbar-release answered HTTP {code} for {what} ({word})"),
        });
    }
    match out {
        Some(path) => {
            std::fs::copy(&body, path)
                .map_err(|error| format!("oracle: cannot keep {what}: {error}"))?;
            Ok(Vec::new())
        }
        None => {
            std::fs::read(&body).map_err(|error| format!("oracle: cannot read {what}: {error}"))
        }
    }
}

/// busbar-release's API root.
const ORACLE_RELEASE_API: &str = "https://api.github.com/repos/GetBusbar/busbar-release";

/// Every dev-bin asset as `(id, name)`.
fn judge_assets() -> Result<Vec<(String, String)>, String> {
    let release = release_api(
        &format!("{ORACLE_RELEASE_API}/releases/tags/dev-bin"),
        "application/vnd.github+json",
        None,
        &format!("{ORACLE_RELEASE_API}/releases/tags/dev-bin"),
    )?;
    let release = Node::parse(&String::from_utf8_lossy(&release)).unwrap_or(Node::Null);
    let rid = match release.get("id") {
        Some(Node::Number(lexeme)) if lexeme.bytes().all(|b| b.is_ascii_digit()) => lexeme.clone(),
        _ => {
            return Err(String::from(
                "oracle: busbar-release has no dev-bin release",
            ))
        }
    };
    let mut assets = Vec::new();
    for page in 1..=20 {
        let url = format!("{ORACLE_RELEASE_API}/releases/{rid}/assets?per_page=100&page={page}");
        let body = release_api(&url, "application/vnd.github+json", None, &url)?;
        let listed = Node::parse(&String::from_utf8_lossy(&body)).unwrap_or(Node::Null);
        let items = listed.as_array().cloned().unwrap_or_default();
        let count = items.len();
        for item in &items {
            let id = match item.get("id") {
                Some(Node::Number(lexeme)) => lexeme.clone(),
                _ => String::from("null"),
            };
            let name = item.get("name").and_then(Node::as_str).unwrap_or("null");
            assets.push((id, String::from(name)));
        }
        if count < 100 {
            break;
        }
    }
    Ok(assets)
}

/// Where a judge's assets come from: a directory (the selftest's fixture release) or the API.
pub(crate) enum Source {
    Dir(PathBuf),
    Api,
}

/// One asset of the source, into `out`; whether it was there.
fn fetch_asset(source: &AssetSource, name: &str, out: &Path) -> bool {
    match source {
        AssetSource::Dir(dir) => {
            let from = dir.join(name);
            from.is_file() && std::fs::copy(&from, out).is_ok()
        }
        AssetSource::Listed(assets) => {
            let Some((id, _)) = assets.iter().find(|(_, asset)| asset == name) else {
                return false;
            };
            release_api(
                &format!("{ORACLE_RELEASE_API}/releases/assets/{id}"),
                "application/octet-stream",
                Some(out),
                &format!("the asset {name}"),
            )
            .is_ok()
        }
    }
}

enum AssetSource {
    Dir(PathBuf),
    Listed(Vec<(String, String)>),
}

// ---- the signature -------------------------------------------------------------------------------

/// The trusted release keys a judge's `.sig` may verify with (busbar-release-cli update.rs
/// RELEASE_KEYS, same keys, same order): busbar-release-2026-10-28, the owner's key that signs every
/// judge from 2026-10-28. The earlier key busbar-release-2026-10-09 is NOT trusted (owner ruling
/// 2026-10-28: its private half lived in GitHub).
pub(crate) const ORACLE_RELEASE_KEY_PEMS: [&str; 1] = ["-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAHC1U0BcT6iFe98mWXNriKeDNxO6xOaoMY5UXotNweEs=\n\
-----END PUBLIC KEY-----"];

/// The judge's `.sig` (base64, Ed25519 over `"<asset name>\n<sha256>\n"`) verifies under any of the
/// keys.
pub(crate) fn verify_judge_sig(
    name: &str,
    hex: &str,
    sig: &Path,
    keys: &[String],
) -> Result<(), String> {
    let openssl = Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !openssl {
        return Err(format!(
            "oracle: refusing the judge: {name} has a .sig and there is no openssl to verify it"
        ));
    }
    let scratch = TempDir::new(&temp_base(), "busbar-oracle-sig.")
        .map_err(|error| format!("oracle: cannot make a scratch dir: {error}"))?;
    let dir = scratch.path();
    let write = |file: &str, bytes: &[u8]| std::fs::write(dir.join(file), bytes);
    write("msg", format!("{name}\n{hex}\n").as_bytes()).map_err(|error| error.to_string())?;
    let verified = std::fs::read_to_string(sig)
        .ok()
        .and_then(|text| base64_decode(&text))
        .is_some_and(|raw| {
            if write("sig", &raw).is_err() {
                return false;
            }
            keys.iter().enumerate().any(|(index, pem)| {
                let key = format!("key{}.pem", index + 1);
                if write(&key, format!("{pem}\n").as_bytes()).is_err() {
                    return false;
                }
                Command::new("openssl")
                    .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
                    .arg(dir.join(&key))
                    .arg("-rawin")
                    .arg("-in")
                    .arg(dir.join("msg"))
                    .arg("-sigfile")
                    .arg(dir.join("sig"))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|status| status.success())
            })
        });
    if verified {
        Ok(())
    } else {
        Err(format!(
            "oracle: refusing the judge: {name}'s .sig is not a signature of it by any of busbar-release's {} trusted release key(s)",
            keys.len()
        ))
    }
}

// ---- the fetched judge ---------------------------------------------------------------------------

/// The pinned judge, fetched and verified: `busbar-oracle-linux-<arch>-<ref>` whose sha256 is the
/// pin's `sha256_linux_<arch>` line, its `.sha256` and `.sig` (when published) agreeing, cached by
/// digest and environment and re-hashed on every use. Prints the path on success.
pub(crate) fn fetch_judge(
    pin: &str,
    cache: &Path,
    source: &Source,
    keys: &[String],
) -> Result<PathBuf, Fail> {
    let arch = judge_arch();
    let rref = pin_in(pin, "release_ref");
    let want = pin_in(pin, &format!("sha256_linux_{arch}"));
    if !is_hex(&rref, 40) {
        return Err(Fail::new(
            1,
            "oracle: no judge: the pin names no full 40-hex release_ref",
        ));
    }
    if !is_hex(&want, 64) {
        return Err(Fail::new(
            1,
            format!(
                "oracle: no judge: the pin has no sha256_linux_{arch} line, and a host whose architecture the pin does not name has no judge"
            ),
        ));
    }
    let name = format!("busbar-oracle-linux-{arch}-{rref}");
    // Cached by its digest AND the environment it was fetched on: never reused on another.
    let bin = cache.join(&want).join(judge_env()).join("busbar-oracle");
    if is_executable(&bin) && sha256_of(&bin).as_deref() == Some(want.as_str()) {
        if judge_starts(&bin) {
            return Ok(bin);
        }
        eprintln!(
            "oracle: the cached judge {} does not start here; deleting it and fetching again",
            bin.display()
        );
        let _ = std::fs::remove_file(&bin);
    }
    let tmp = TempDir::new(&temp_base(), "busbar-oracle-fetch.")
        .map_err(|error| Fail::new(1, format!("oracle: cannot make a scratch dir: {error}")))?;
    let assets = match source {
        Source::Dir(dir) => AssetSource::Dir(dir.clone()),
        Source::Api => {
            eprintln!(
                "oracle: fetching the judge {name} from busbar-release's dev-bin release ({})",
                token_word()
            );
            AssetSource::Listed(judge_assets().map_err(|message| Fail::new(1, message))?)
        }
    };
    let fetched = tmp.path().join(&name);
    if !fetch_asset(&assets, &name, &fetched) {
        return Err(Fail::new(
            1,
            format!("oracle: no judge: {name} is not on busbar-release's dev-bin release"),
        ));
    }
    let got = sha256_of(&fetched).unwrap_or_default();
    if got != want {
        return Err(Fail::new(
            1,
            format!("oracle: refusing the judge: {name} has sha256 {got}, the pin says {want}"),
        ));
    }
    let side_path = tmp.path().join(format!("{name}.sha256"));
    if fetch_asset(&assets, &format!("{name}.sha256"), &side_path) {
        let side: String = std::fs::read_to_string(&side_path)
            .unwrap_or_default()
            .chars()
            .take(64)
            .collect();
        if side != want {
            return Err(Fail::new(
                1,
                format!("oracle: refusing the judge: its published .sha256 ({side}) is not the pin's {want}"),
            ));
        }
    }
    let sig_path = tmp.path().join(format!("{name}.sig"));
    if fetch_asset(&assets, &format!("{name}.sig"), &sig_path) {
        verify_judge_sig(&name, &got, &sig_path, keys).map_err(|message| Fail::new(1, message))?;
    }
    let parent = bin.parent().unwrap_or(cache);
    std::fs::create_dir_all(parent).map_err(|error| {
        Fail::new(
            1,
            format!("oracle: cannot make {}: {error}", parent.display()),
        )
    })?;
    let part = PathBuf::from(format!("{}.part", bin.display()));
    std::fs::copy(&fetched, &part)
        .and_then(|_| make_executable(&part))
        .and_then(|()| std::fs::rename(&part, &bin))
        .map_err(|error| Fail::new(1, format!("oracle: cannot place the judge: {error}")))?;
    drop(tmp);
    if !judge_starts(&bin) {
        let help = Command::new(&bin)
            .arg("--help")
            .stdin(Stdio::null())
            .output()
            .map(|output| {
                let mut all = String::from_utf8_lossy(&output.stdout).into_owned();
                all.push_str(&String::from_utf8_lossy(&output.stderr));
                all.lines().take(3).collect::<Vec<_>>().join("\n")
            })
            .unwrap_or_default();
        let _ = std::fs::remove_file(&bin);
        return Err(Fail::new(
            1,
            format!(
                "oracle: no judge: the fetched {name} does not start on this host ({}): {help}",
                judge_env()
            ),
        ));
    }
    Ok(bin)
}

// ---- the pin: the branch file's env, nothing else ------------------------------------------------

/// `(env var, pin key)` for every field of the judge's pin.
const ORACLE_ENV_KEYS: [(&str, &str); 6] = [
    ("BUSBAR_ORACLE_RELEASE_REPO", "release_repo"),
    ("BUSBAR_ORACLE_RELEASE_REF", "release_ref"),
    ("BUSBAR_ORACLE_SHA256_LINUX_X86_64", "sha256_linux_x86_64"),
    ("BUSBAR_ORACLE_SHA256_LINUX_AARCH64", "sha256_linux_aarch64"),
    ("BUSBAR_ORACLE_CRATE", "crate"),
    ("BUSBAR_ORACLE_BIN", "bin"),
];

/// The branch file's judge pin text; NO JUDGE when any key is unset.
pub(crate) fn env_judge_pin() -> Result<String, Fail> {
    let missing: String = ORACLE_ENV_KEYS
        .iter()
        .filter(|(name, _)| var(name).is_empty())
        .map(|(name, _)| format!(" {name}"))
        .collect();
    if !missing.is_empty() {
        return Err(Fail::new(
            1,
            format!(
                "oracle: NO JUDGE: the environment sets no{missing}. The judge is named by the branch file's env only (busbar modernci-config .ci/*.yaml). Refusing."
            ),
        ));
    }
    Ok(ORACLE_ENV_KEYS
        .iter()
        .map(|(name, key)| format!("{key}={}\n", var(name)))
        .collect())
}

/// The env variable holding this host's judge digest.
pub(crate) fn judge_want_var() -> String {
    format!("BUSBAR_ORACLE_SHA256_LINUX_{}", judge_arch().to_uppercase())
}

// ---- the 1.5.5 golden, from the object database --------------------------------------------------

const ORACLE_GOLDEN_REL: &str = "testing/shadow-oracle/golden/1.5.5";

/// The candidate's data dir: `$BUSBAR_ORACLE_DATA`, else the shim's own checkout's.
pub(crate) fn cand_data(here: &Path) -> PathBuf {
    let data = var("BUSBAR_ORACLE_DATA");
    if data.is_empty() {
        here.join("testing/shadow-oracle")
    } else {
        PathBuf::from(data)
    }
}

/// `BUSBAR_GOLDEN_1_5_5_TREE`, from `repo`'s object database, into `out`.
fn odb_golden(repo: &Path, out: &Path) -> Result<(), Fail> {
    let want = var("BUSBAR_GOLDEN_1_5_5_TREE");
    if !is_hex(&want, 40) {
        return Err(Fail::new(
            1,
            format!(
                "oracle: NO GOLDEN: ModernCI's config names no 40-hex BUSBAR_GOLDEN_1_5_5_TREE ('{}'). Refusing.",
                if want.is_empty() { "unset" } else { &want }
            ),
        ));
    }
    let git = |args: &[&str]| -> Option<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    if git(&["cat-file", "-t", &want]).as_deref() != Some("tree") {
        return Err(Fail::new(
            1,
            format!(
                "oracle: NO GOLDEN: BUSBAR_GOLDEN_1_5_5_TREE {want} is not a tree in this checkout's object database. Refusing."
            ),
        ));
    }
    let got = git(&[
        "rev-parse",
        "-q",
        "--verify",
        &format!("HEAD:{ORACLE_GOLDEN_REL}"),
    ])
    .unwrap_or_else(|| String::from("<none>"));
    if got != want {
        return Err(Fail::new(
            1,
            format!(
                "oracle: the candidate's {ORACLE_GOLDEN_REL} is tree {got}, ModernCI's BUSBAR_GOLDEN_1_5_5_TREE is {want} (a golden change is a config change). Refusing."
            ),
        ));
    }
    let _ = std::fs::remove_dir_all(out);
    std::fs::create_dir_all(out).map_err(|error| Fail::new(1, error.to_string()))?;
    let mut archive = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["archive", "--format=tar", &want])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| Fail::new(1, format!("oracle: cannot run git archive: {error}")))?;
    let piped = archive
        .stdout
        .take()
        .ok_or_else(|| Fail::new(1, "oracle: git archive has no stdout"))?;
    let untar = Command::new("tar")
        .args(["-xf", "-", "-C"])
        .arg(out)
        .stdin(Stdio::from(piped))
        .status()
        .map_err(|error| Fail::new(1, format!("oracle: cannot run tar: {error}")))?;
    let archived = archive
        .wait()
        .map_err(|error| Fail::new(1, error.to_string()))?;
    if untar.success() && archived.success() {
        Ok(())
    } else {
        Err(Fail::new(1, ""))
    }
}

/// Under ModernCI every `--golden` in `args` becomes `BUSBAR_GOLDEN_1_5_5_TREE` read from the
/// candidate's object database; a refusal when none can be.
pub(crate) fn modernci_golden(
    here: &Path,
    cache_home: &Path,
    args: &mut [String],
) -> Result<(), Fail> {
    let data = cand_data(here);
    let root = Command::new("git")
        .arg("-C")
        .arg(&data)
        .args(["rev-parse", "--show-toplevel"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()))
        .ok_or_else(|| {
            Fail::new(
                1,
                format!(
                    "oracle: NO GOLDEN: the candidate's data dir {} is in no git checkout. Refusing.",
                    data.display()
                ),
            )
        })?;
    let gdir = TempDir::new(cache_home, "oracle-golden-odb.")
        .map_err(|error| Fail::new(1, format!("oracle: cannot make a scratch dir: {error}")))?
        .keep();
    odb_golden(&root, &gdir)?;
    let gdir_text = gdir.to_string_lossy().into_owned();
    for index in 0..args.len() {
        if args[index] == "--golden" {
            if let Some(next) = args.get_mut(index + 1) {
                next.clone_from(&gdir_text);
            }
        }
        if args[index].starts_with("--golden=") {
            args[index] = format!("--golden={gdir_text}");
        }
    }
    eprintln!(
        "oracle: the 1.5.5 golden is tree {}, read from the object database (never the worktree)",
        var("BUSBAR_GOLDEN_1_5_5_TREE")
    );
    Ok(())
}

// ---- which binary is the judge --------------------------------------------------------------------

/// What `resolve_bin` needs of the run: the checkout, the caches and the judge's names.
pub(crate) struct Cfg {
    pub(crate) here: PathBuf,
    pub(crate) cache_home: PathBuf,
    pub(crate) release_repo: String,
    pub(crate) release_ref: String,
    pub(crate) crate_name: String,
    pub(crate) bin_name: String,
    /// `<target>/oracle/rust/<ref>`.
    pub(crate) root: PathBuf,
    /// The generated tool dir beside it.
    pub(crate) shim_dir: PathBuf,
}

impl Cfg {
    /// The run's configuration from the environment; the ref names one directory or it is refused.
    pub(crate) fn from_env(here: &Path) -> Result<Self, Fail> {
        let cache_home = {
            let dir = var("MODERNCI_CACHE_DIR");
            if dir.is_empty() {
                here.join("target")
            } else {
                PathBuf::from(dir)
            }
        };
        let release_ref = {
            let value = var("BUSBAR_ORACLE_RELEASE_REF");
            if value.is_empty() {
                String::from("none")
            } else {
                value
            }
        };
        if release_ref == "."
            || release_ref == ".."
            || release_ref.contains('/')
            || release_ref.contains('\\')
        {
            return Err(Fail::new(
                2,
                format!(
                    "oracle: BUSBAR_ORACLE_RELEASE_REF is not a single ref name: {release_ref}"
                ),
            ));
        }
        let target = {
            let dir = var("CARGO_TARGET_DIR");
            if dir.is_empty() {
                here.join("target")
            } else {
                PathBuf::from(dir)
            }
        };
        let root = target.join("oracle/rust").join(&release_ref);
        let named = |name: &str, default: &str| {
            let value = var(name);
            if value.is_empty() {
                String::from(default)
            } else {
                value
            }
        };
        Ok(Self {
            here: here.to_path_buf(),
            cache_home,
            release_repo: var("BUSBAR_ORACLE_RELEASE_REPO"),
            release_ref,
            crate_name: named("BUSBAR_ORACLE_CRATE", "busbar-release-oracle"),
            bin_name: named("BUSBAR_ORACLE_BIN", "busbar-oracle"),
            shim_dir: root.join("tool"),
            root,
        })
    }
}

/// The path cargo reported as the built executable (`"executable":"<path>"`, the last one).
fn executable_in(artifacts: &str) -> Option<String> {
    artifacts
        .lines()
        .filter_map(|line| {
            let start = line.find("\"executable\":\"")? + "\"executable\":\"".len();
            let rest = &line[start..];
            Some(String::from(&rest[..rest.find('"')?]))
        })
        .next_back()
}

/// Which file is the judge: ModernCI's, held to the config's digest; an operator's
/// `BUSBAR_ORACLE_RUST_BIN` outside CI; on Linux the fetched, pinned judge; elsewhere a
/// busbar-release checkout built.
pub(crate) fn resolve_bin(cfg: &Cfg) -> Result<PathBuf, Fail> {
    let operator = var("BUSBAR_ORACLE_RUST_BIN");
    // NO CI RUN TAKES BUSBAR_ORACLE_RUST_BIN: it names a binary the job's own environment chose.
    if !operator.is_empty() && ci_run() {
        eprintln!(
            "oracle: ignoring BUSBAR_ORACLE_RUST_BIN ({operator}): a CI run's judge is ModernCI's, never an operator's binary"
        );
    }
    // UNDER MODERNCI the only judge is the config's: its pin first, then the file ModernCI
    // pre-fetched outside the run, at the config's digest. Never a fetch, never a source build.
    if under_modernci() {
        env_judge_pin()?;
        let digest_var = judge_want_var();
        let path = var("BUSBAR_ORACLE_JUDGE_PATH");
        if path.is_empty() {
            return Err(Fail::new(
                1,
                "oracle: NO JUDGE: ModernCI handed over no BUSBAR_ORACLE_JUDGE_PATH (its tool pin busbar-oracle-judge, .ci/oracle-judge.pin, fetched outside the run). A check never fetches the judge and never reads a token. Refusing.",
            ));
        }
        let want = var(&digest_var);
        if want.is_empty() {
            return Err(Fail::new(
                1,
                format!(
                    "oracle: NO JUDGE: BUSBAR_ORACLE_JUDGE_PATH ({path}) is set but ModernCI's config sets no {digest_var} to verify it against. Refusing."
                ),
            ));
        }
        let judge = PathBuf::from(&path);
        let got = if judge.is_file() {
            sha256_of(&judge).unwrap_or_default()
        } else {
            String::new()
        };
        if got != want {
            return Err(Fail::new(
                1,
                format!(
                    "oracle: NO JUDGE: BUSBAR_ORACLE_JUDGE_PATH ({path}) has sha256 '{}', not ModernCI's {digest_var} ('{want}'). Refusing.",
                    if got.is_empty() { "<unreadable>" } else { &got }
                ),
            ));
        }
        if !is_executable(&judge) {
            return Err(Fail::new(
                1,
                format!("oracle: NO JUDGE: BUSBAR_ORACLE_JUDGE_PATH ({path}) is not executable. Refusing."),
            ));
        }
        return Ok(judge);
    }
    if !operator.is_empty() {
        let bin = PathBuf::from(&operator);
        if !is_executable(&bin) {
            return Err(Fail::new(
                1,
                format!("oracle: BUSBAR_ORACLE_RUST_BIN is not executable: {operator}"),
            ));
        }
        return Ok(bin);
    }
    if host_os() == "linux" {
        let pin = env_judge_pin()?;
        let keys: Vec<String> = ORACLE_RELEASE_KEY_PEMS
            .iter()
            .map(|pem| String::from(*pem))
            .collect();
        return fetch_judge(
            &pin,
            &cfg.cache_home.join("busbar-oracle-judge"),
            &Source::Api,
            &keys,
        );
    }
    let prebuilt = cfg.root.join("checkout/target/release").join(&cfg.bin_name);
    if is_executable(&prebuilt) {
        return Ok(prebuilt);
    }
    let checkout = {
        let named = var("BUSBAR_RELEASE_CHECKOUT");
        if named.is_empty() {
            // busbar-release is a PRIVATE first-party repo: stage the engine checkout, then build.
            let dir = cfg.root.join("checkout");
            clone_engine(&cfg.release_repo, &cfg.release_ref, &dir)?;
            dir
        } else {
            PathBuf::from(named)
        }
    };
    // ASK CARGO WHERE IT PUT THE BINARY; never assume `<checkout>/target/release`: a caller's own
    // target directory (CARGO_TARGET_DIR, `[build] target-dir`) puts it elsewhere.
    let output = Command::new("cargo")
        .current_dir(&checkout)
        .args(["build", "--locked", "--release", "-p"])
        .arg(&cfg.crate_name)
        .arg("--bin")
        .arg(&cfg.bin_name)
        .arg("--message-format=json-render-diagnostics")
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| Fail::new(1, format!("oracle: cannot run cargo: {error}")))?;
    if !output.status.success() {
        return Err(Fail::new(
            output
                .status
                .code()
                .map_or(1, |c| u8::try_from(c & 0xff).unwrap_or(1)),
            "",
        ));
    }
    let built = executable_in(&String::from_utf8_lossy(&output.stdout))
        .map(PathBuf::from)
        .unwrap_or_else(|| checkout.join("target/release").join(&cfg.bin_name));
    if !is_executable(&built) {
        return Err(Fail::new(
            1,
            format!(
                "oracle: build produced no {} (cargo reported {}; checkout {})",
                cfg.bin_name,
                built.display(),
                checkout.display()
            ),
        ));
    }
    Ok(built)
}
