// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::sign::sha256_hex;
use std::path::{Component, Path};

fn filename_is_single_component(filename: &str) -> bool {
    let mut comps = Path::new(filename).components();
    matches!(comps.next(), Some(Component::Normal(_))) && comps.next().is_none()
}

fn printable_url(url: &str) -> std::borrow::Cow<'_, str> {
    let (scheme, rest) = match url.find("://") {
        Some(i) => url.split_at(i + 3),
        None => ("", url),
    };
    let authority_end = if scheme.is_empty() {
        0
    } else {
        rest.find(['/', '?', '#']).unwrap_or(rest.len())
    };
    let host_from = rest[..authority_end].rfind('@').map_or(0, |at| at + 1);
    let tail = &rest[host_from..];
    let tail_cut = tail
        .find(['?', '#'])
        .filter(|&i| i + 1 < tail.len())
        .map(|i| (i, &tail[i..=i]));
    if host_from == 0 && tail_cut.is_none() {
        return std::borrow::Cow::Borrowed(url);
    }
    let mut shown = String::with_capacity(url.len());
    shown.push_str(scheme);
    match tail_cut {
        Some((i, delim)) => {
            shown.push_str(&tail[..i]);
            shown.push_str(delim);
            shown.push_str("<redacted>");
        }
        None => shown.push_str(tail),
    }
    std::borrow::Cow::Owned(shown)
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
    /// `url`, and the URL inside `error`, are the printable URL (no userinfo, no query): this
    /// outcome exists to be logged.
    Warned { url: String, error: String },
}

pub type Downloader<'a> = dyn Fn(&str) -> Result<Vec<u8>, String> + 'a;

#[cold]
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
        let record_problem = |errors: &mut Vec<String>,
                              outcomes: &mut Vec<FetchOutcome>,
                              msg: String| {
            let shown = printable_url(&spec.url);
            let error = msg.replace(spec.url.as_str(), &shown);
            if fatal_on_miss {
                errors.push(error);
            } else {
                tracing::warn!(url = %shown, %error, "plugin fetch problem (reload); keeping the current artifact");
                outcomes.push(FetchOutcome::Warned {
                    url: shown.into_owned(),
                    error,
                });
            }
        };

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

        let bytes = match download(&spec.url) {
            Ok(b) => b,
            Err(e) => {
                record_problem(&mut errors, &mut outcomes, format!("download failed: {e}"));
                continue;
            }
        };

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

        let unchanged = std::fs::read(&target)
            .is_ok_and(|installed| sha256_hex(&installed) == sha256_hex(&bytes));
        if !unchanged {
            if let Err(refusal) = fresh(&bytes) {
                record_problem(&mut errors, &mut outcomes, format!(
                    "release seal refused ({}): {refusal} (not written; a NEW download is judged at install time, and any installed copy is kept)", refusal.code()));
                continue;
            }
        }

        match crate::durable::write(&dir.join(&spec.filename), &bytes).map_err(|e| e.to_string()) {
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

fn fresh(bytes: &[u8]) -> Result<(), crate::release_trust::SealRefusal> {
    let Ok(unpacked) = crate::tarball::unpack(bytes) else {
        return Ok(());
    };
    if unpacked.manifest.publisher != crate::sign::FIRST_PARTY_PUBLISHER {
        return Ok(());
    }
    match crate::release_trust::wire::read_seal(&unpacked.manifest.signature) {
        None => Ok(()),
        Some(Err(why)) => Err(crate::release_trust::SealRefusal::Malformed {
            doc: "release seal",
            why,
        }),
        Some(Ok((keys, targets))) => crate::release_trust::check_fresh(
            crate::release_trust::Seal {
                keys: &keys,
                targets: &targets,
            },
            crate::release_trust::now(),
        ),
    }
}

#[cfg(test)]
#[path = "tests/fetch_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/fetch_url_scrub_tests.rs"]
mod url_scrub_tests;
