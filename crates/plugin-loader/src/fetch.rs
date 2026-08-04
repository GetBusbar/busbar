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
use std::path::Path;

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
mod tests {
    use super::*;

    fn tmpdir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let mut rnd = [0u8; 8];
        let _ = getrandom::fill(&mut rnd);
        p.push(format!(
            "busbar-fetch-test-{}",
            rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn spec(url: &str, sha: Option<&str>, file: &str) -> FetchSpec {
        FetchSpec {
            url: url.into(),
            sha256: sha.map(str::to_string),
            filename: file.into(),
        }
    }

    /// A pre-placed tarball hashing to the pin ⇒ Cached, and the (bogus, would-panic) downloader is
    /// NEVER called.
    #[test]
    fn cached_by_pin_skips_network() {
        let dir = tmpdir();
        let body = b"the-real-signed-tarball";
        std::fs::write(dir.join("plugin.tar.gz"), body).unwrap();
        let pin = sha256_hex(body);

        let never = |_: &str| -> Result<Vec<u8>, String> { panic!("network must not be touched") };
        let out = fetch_plugins(
            &dir,
            &[spec("https://x/plugin.tar.gz", Some(&pin), "plugin.tar.gz")],
            true,
            &never,
        )
        .unwrap();
        assert_eq!(
            out,
            vec![FetchOutcome::Cached {
                filename: "plugin.tar.gz".into()
            }]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Served bytes ≠ pin ⇒ error, and `dir` is unchanged (no file written).
    #[test]
    fn hash_mismatch_never_writes() {
        let dir = tmpdir();
        let pin = sha256_hex(b"expected");
        let dl = |_: &str| Ok(b"WRONG-BYTES".to_vec());
        let err = fetch_plugins(
            &dir,
            &[spec("https://x/p.tar.gz", Some(&pin), "p.tar.gz")],
            true,
            &dl,
        )
        .unwrap_err();
        assert!(err[0].contains("mismatch"), "{err:?}");
        assert!(
            !dir.join("p.tar.gz").exists(),
            "no file must be written on mismatch"
        );
        // No leftover temp files either.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(leftovers.is_empty(), "dir must be unchanged: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unreachable spec: boot (fatal=true) ⇒ Err; reload (fatal=false) ⇒ Ok + Warned.
    #[test]
    fn boot_miss_fatal_reload_miss_warns() {
        let dir = tmpdir();
        let dead = |_: &str| -> Result<Vec<u8>, String> { Err("connection refused".into()) };
        let s = [spec(
            "https://unreachable/p.tar.gz",
            Some("deadbeef"),
            "p.tar.gz",
        )];

        assert!(
            fetch_plugins(&dir, &s, true, &dead).is_err(),
            "boot miss must be fatal"
        );

        let out = fetch_plugins(&dir, &s, false, &dead).unwrap();
        assert!(
            matches!(out.as_slice(), [FetchOutcome::Warned { .. }]),
            "reload miss must warn: {out:?}"
        );
        assert!(!dir.join("p.tar.gz").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A verified download is written atomically and readable back byte-for-byte.
    #[test]
    fn verified_download_is_written() {
        let dir = tmpdir();
        let body = b"fresh-tarball-bytes";
        let pin = sha256_hex(body);
        let dl = |_: &str| Ok(body.to_vec());
        let out = fetch_plugins(
            &dir,
            &[spec("https://x/p.tar.gz", Some(&pin), "p.tar.gz")],
            true,
            &dl,
        )
        .unwrap();
        assert_eq!(
            out,
            vec![FetchOutcome::Fetched {
                filename: "p.tar.gz".into()
            }]
        );
        assert_eq!(std::fs::read(dir.join("p.tar.gz")).unwrap(), body);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
