// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Declarative plugin FETCH (`plugins.fetch:`): download the signed tarballs an operator declared
//! into `plugins.dir` BEFORE the loader scans it. This is an INTEGRITY + CACHE layer only — it never
//! `dlopen`s, evaluates trust, or parses a manifest; the unchanged `scan_and_validate` signature
//! check remains the sole trust gate over whatever bytes land here.
//!
//! ## Contract
//! - **Cache-by-pin.** A `sha256`-pinned spec whose target file already hashes to the pin skips the
//!   network entirely ([`FetchOutcome::Cached`]).
//! - **Verify-before-write + atomic rename.** A download is hashed against the pin IN MEMORY; only on
//!   a match are the bytes written to a temp file and atomically `rename`d into place. A hash
//!   mismatch, a download error, or a write error NEVER leaves a partial or wrong file in `dir`.
//! - **Boot fatal / reload warn.** `fatal_on_miss` (the caller's `prior.is_none()` boot/reload
//!   discriminator) decides whether an unreachable/mismatched spec fails the whole call (`Err`) or is
//!   recorded as a [`FetchOutcome::Warned`] so a running node keeps serving what it already has.
//!
//! ## Why the downloader is injected
//! `plugin-loader` deliberately carries no HTTP client (and starts no tokio runtime). The engine
//! crate owns the network stack AND the cloud-metadata SSRF denylist, so it passes a `download`
//! closure that performs the GET under those guards. This keeps the fetch policy (cache / verify /
//! atomic write / boot-vs-reload) pure and unit-testable with a fake downloader, and keeps SSRF
//! enforcement in the one crate that has the denylist.

use busbar_plugin_sign::sha256_hex;
use std::path::{Component, Path};

use serde::Deserialize;

// ── THE `plugins.fetch:` GRAMMAR ────────────────────────────────────────────────────────────────
//
// The operator's `plugins.fetch:` entries and the lowering that turns one of them into a
// [`FetchSpec`]. It is DECLARED HERE, beside the machinery that consumes it, because the grammar of
// a subsystem's config section is that subsystem's own face: the engine parses a document and hands
// the loader what the loader's own types say the words mean, rather than owning a second spelling of
// them. The engine re-exports every item below at its historical `config::` path, so its own call
// sites are unchanged.

/// One `plugins.fetch:` entry — an UNTAGGED enum discriminated by which key is present. `github` is a
/// `org/repo@tag` release ref (asset resolved by the loader); `url` is a direct tarball URL; `env`
/// names an environment variable holding a URL (or `url@sha256`). `sha256` (github/url) is the
/// lowercase-hex integrity pin: it is BOTH the download-skip cache key (a file in `dir` already
/// hashing to it ⇒ no network) and the verify-before-write gate. Per-variant `deny_unknown_fields`
/// so a typo'd key can't be silently reinterpreted as a different variant.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum PluginFetch {
    /// `- { github: "org/repo@v1.2.3", sha256?: "…" }`
    Github(GithubFetch),
    /// `- { url: "https://host/plugin.tar.gz", sha256?: "…" }`
    Url(UrlFetch),
    /// `- { env: "BUSBAR_PLUGIN_URL" }` (the VAR holds a url, or `url@sha256`)
    Env(EnvFetch),
}

/// The `{ github, sha256? }` fetch shape. `deny_unknown_fields` on each variant struct is what gives
/// the untagged enum real typo rejection: an entry with a stray key matches NO variant and errors,
/// rather than being silently reinterpreted.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GithubFetch {
    pub github: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

/// The `{ url, sha256? }` fetch shape.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UrlFetch {
    pub url: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

/// The `{ env }` fetch shape (the VAR's value is a url, optionally `url@sha256`).
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvFetch {
    pub env: String,
}

/// The tarball filename inside `plugins.dir` a fetch URL writes to: the last path segment (before any
/// `?`/`#`), which must be non-empty. Errors if the URL has no usable basename.
pub fn fetch_filename_from_url(url: &str) -> Result<String, String> {
    let path = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let base = path.rsplit('/').next().unwrap_or("");
    if base.is_empty() {
        return Err(format!(
            "plugins.fetch url '{url}' has no filename (a signed tarball basename is required)"
        ));
    }
    Ok(base.to_string())
}

/// Map one [`PluginFetch`] to a [`FetchSpec`].
pub fn spec_from(f: &PluginFetch) -> Result<FetchSpec, String> {
    match f {
        PluginFetch::Github(g) => {
            // "org/repo@tag" → the GitHub release-asset URL. busbar plugins ship one signed
            // `{repo}.tar.gz` per release, so the asset name is derived, not discovered.
            let (repo_path, tag) = g.github.split_once('@').ok_or_else(|| {
                format!(
                    "plugins.fetch github '{}' must be 'org/repo@tag' (missing '@tag')",
                    g.github
                )
            })?;
            let (org, repo) = repo_path.split_once('/').ok_or_else(|| {
                format!(
                    "plugins.fetch github '{}' must be 'org/repo@tag' (missing 'org/repo')",
                    g.github
                )
            })?;
            if org.is_empty() || repo.is_empty() || tag.is_empty() {
                return Err(format!(
                    "plugins.fetch github '{}' must be a non-empty 'org/repo@tag'",
                    g.github
                ));
            }
            let filename = format!("{repo}.tar.gz");
            let url = format!("https://github.com/{org}/{repo}/releases/download/{tag}/{filename}");
            Ok(FetchSpec {
                url,
                sha256: g.sha256.clone(),
                filename,
            })
        }
        PluginFetch::Url(u) => Ok(FetchSpec {
            url: u.url.clone(),
            sha256: u.sha256.clone(),
            filename: fetch_filename_from_url(&u.url)?,
        }),
        PluginFetch::Env(e) => {
            let raw = std::env::var(&e.env).map_err(|_| {
                format!(
                    "plugins.fetch env '{}' is not set (it must hold a url or 'url@sha256')",
                    e.env
                )
            })?;
            // The var value is `url` or `url@sha256`. Split on the LAST '@' so a userinfo '@' in the
            // URL isn't mistaken for the pin separator (pins are hex, no '@').
            let (url, sha256) = match raw.rsplit_once('@') {
                Some((u, s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    (u.to_string(), Some(s.to_string()))
                }
                _ => (raw.clone(), None),
            };
            Ok(FetchSpec {
                filename: fetch_filename_from_url(&url)?,
                url,
                sha256,
            })
        }
    }
}

/// Reject any `filename` that is not EXACTLY ONE normal path component before it is joined onto
/// `plugins.dir`. A config-driven `filename` of `../../evil` (or an absolute `/etc/evil`, or a nested
/// `a/b`) would otherwise ESCAPE `dir` at the `dir.join(&spec.filename)` sites — a config-driven
/// arbitrary write. This is the SAME single-`Normal`-component guard [`crate::tarball::unpack`]
/// applies to archive entries, lifted to the fetch path so both boundaries refuse traversal the same
/// way. A single ordinary filename (`evil.tar.gz`) is the only shape accepted.
fn filename_is_single_component(filename: &str) -> bool {
    let mut comps = Path::new(filename).components();
    matches!(comps.next(), Some(Component::Normal(_))) && comps.next().is_none()
}

/// A fully-resolved fetch: the URL to GET, an optional lowercase-hex sha256 pin (cache key +
/// verify-before-write gate), and the target filename inside `plugins.dir`. Produced by the engine's
/// `PluginsCfg::fetch_specs()` (github/url/env → this).
#[derive(Debug, Clone, PartialEq)]
pub struct FetchSpec {
    /// Absolute URL of the signed tarball.
    pub url: String,
    /// Lowercase-hex sha256 integrity pin, if the operator set one.
    pub sha256: Option<String>,
    /// Target filename inside `dir` (never a path — the loader joins it onto `dir`).
    pub filename: String,
}

/// The per-spec result of [`fetch_plugins`].
#[derive(Debug, Clone, PartialEq)]
pub enum FetchOutcome {
    /// The pinned file was already present and hashed to the pin — no network.
    Cached { filename: String },
    /// Downloaded, verified against the pin (if any), and atomically written.
    Fetched { filename: String },
    /// A non-fatal (reload) miss/mismatch: recorded and logged, the node keeps serving what it has.
    Warned { url: String, error: String },
}

/// The injected download callback: URL in, tarball bytes out (or an error message). The engine wires
/// this to its HTTP client under the SSRF denylist.
pub type Downloader<'a> = dyn Fn(&str) -> Result<Vec<u8>, String> + 'a;

/// Fetch every `spec` into `dir`. See the module doc for the full contract. On boot
/// (`fatal_on_miss = true`) any problem aborts with `Err(messages)`; on reload it is collected as a
/// [`FetchOutcome::Warned`] and the call still succeeds.
#[cold] // boot/admin-only — keeps hot text dense (never inlined into a warm path)
#[inline(never)]
pub fn fetch_plugins(
    dir: &Path,
    specs: &[FetchSpec],
    fatal_on_miss: bool,
    download: &Downloader<'_>,
) -> Result<Vec<FetchOutcome>, Vec<String>> {
    let mut outcomes = Vec::new();
    let mut errors = Vec::new();

    for spec in specs {
        // A problem is FATAL at boot (collected into `errors`) and a WARN at reload (recorded as a
        // Warned outcome so serving continues). Either way `dir` is left untouched.
        let record_problem = |errors: &mut Vec<String>,
                              outcomes: &mut Vec<FetchOutcome>,
                              msg: String| {
            if fatal_on_miss {
                errors.push(msg);
            } else {
                tracing::warn!(url = %spec.url, error = %msg, "plugin fetch problem (reload); keeping the current artifact");
                outcomes.push(FetchOutcome::Warned {
                    url: spec.url.clone(),
                    error: msg,
                });
            }
        };

        // Refuse a filename that is not a single normal component BEFORE any join — otherwise a
        // `../../evil` or absolute `filename` escapes `dir` at the probe/write sites below.
        if !filename_is_single_component(&spec.filename) {
            record_problem(
                &mut errors,
                &mut outcomes,
                format!(
                    "refusing unsafe target filename {:?}: it must be a single path component, not a \
                     path (absolute or parent reference)",
                    spec.filename
                ),
            );
            continue;
        }

        let target = dir.join(&spec.filename);

        // Cache-by-pin: a pinned target already hashing to the pin means the exact signed bytes are
        // already on disk — never touch the network.
        if let Some(pin) = &spec.sha256 {
            if let Ok(existing) = std::fs::read(&target) {
                if sha256_hex(&existing).eq_ignore_ascii_case(pin) {
                    outcomes.push(FetchOutcome::Cached {
                        filename: spec.filename.clone(),
                    });
                    continue;
                }
            }
        }

        // Download.
        let bytes = match download(&spec.url) {
            Ok(b) => b,
            Err(e) => {
                record_problem(&mut errors, &mut outcomes, format!("download failed: {e}"));
                continue;
            }
        };

        // Verify-before-write: a mismatched download is NEVER written.
        if let Some(pin) = &spec.sha256 {
            let got = sha256_hex(&bytes);
            if !got.eq_ignore_ascii_case(pin) {
                record_problem(
                    &mut errors,
                    &mut outcomes,
                    format!("sha256 mismatch: expected {pin}, got {got} (not written)"),
                );
                continue;
            }
        }

        // Durable write via the single owner (busbar_api::durable): temp -> fsync -> atomic rename ->
        // parent fsync; no partial or wrong file ever appears at the target.
        match busbar_api::durable::write(&dir.join(&spec.filename), &bytes)
            .map_err(|e| e.to_string())
        {
            Ok(()) => outcomes.push(FetchOutcome::Fetched {
                filename: spec.filename.clone(),
            }),
            Err(e) => record_problem(&mut errors, &mut outcomes, format!("write failed: {e}")),
        }
    }

    if fatal_on_miss && !errors.is_empty() {
        Err(errors)
    } else {
        Ok(outcomes)
    }
}

#[cfg(test)]
#[path = "tests/fetch_tests.rs"]
mod tests;
