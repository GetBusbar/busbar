// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUILT-IN secret resolution: the `env` and `file` modules.
//!
//! The SECRET-MODULE contract itself — [`SecretModule`](busbar_contract::secret::SecretModule) and
//! its error taxonomy — LEFT THIS CRATE for
//! `busbar_contract::secret` (DECISIONS #83/#84; #35(a)) and is re-exported from `lib.rs` under its
//! original names (`SecretError` aliases `busbar_contract::secret::SecretModuleError`, de-collided
//! from `busbar_contract::kinds::SecretError`, #35). What stays here is the machinery — reading the
//! environment and the filesystem is not a shape (#83(b)) — and the neutral [`SecretResolve`] seam,
//! which takes the config [`SecretRef`] and moves with it when the fold merges that crate.

use busbar_contract::secret_ref::{SecretRef, SECRET_MODULE_ENV, SECRET_MODULE_FILE};

/// BUILT-IN resolution of a secret reference to its raw bytes: `env` reads the
/// environment variable; `file` reads the file. Any other module name is FAIL-CLOSED here - the
/// full secret-plugin resolver (third-party `kind: secret` modules through the plugin trust
/// pipeline) is layered on top of this by the engine's `SecretResolver`, which falls back to these
/// built-ins by these exact names.
pub fn resolve_builtin(secret: &SecretRef) -> Result<Vec<u8>, String> {
    // `none` is a DECLARATION, not a source: it says there is no credential at all. Asking a
    // resolver for its bytes is a category error, so it is a hard error here rather than "resolves
    // to empty" — an empty secret is precisely what the fail-closed posture exists to prevent. The
    // one call site that legitimately accepts an absent credential (a provider `api_key` for a
    // keyless upstream) tests `SecretRef::is_none()` and never reaches a resolver at all.
    if secret.is_none() {
        return Err(
            "the `none` secret reference declares that there is NO credential, so it has no value \
             to resolve; it is accepted only where an absent credential is meaningful (a provider \
             `api_key` for a keyless upstream such as ollama or vLLM)"
                .to_string(),
        );
    }
    if let Some(var) = self_env_var_checked(secret)? {
        // `std::env::var` collapses two DIFFERENT operator errors into one `Err`: `NotPresent` (the
        // variable is absent) and `NotUnicode` (it is SET, and its value is not UTF-8). Reporting
        // both as "unset" is a wrong diagnosis rather than a missing one — an operator told their
        // variable is unset will set it again, which is the one action that cannot fix a value that
        // is already there and mis-encoded. `var_os` keeps the two apart: `None` is genuinely
        // absent, `Some(raw)` that fails `into_string` is present-but-unusable.
        return match std::env::var_os(&var) {
            None => Err(format!(
                "secret env:{var} cannot resolve: environment variable '{var}' is unset"
            )),
            // The mis-encoded value is DROPPED, never quoted back: the whole point of this branch
            // is that the variable holds a credential, and an error message is not a place to put
            // one. Naming the variable is enough to act on.
            Some(raw) => match raw.into_string() {
                Err(_) => Err(format!(
                    "secret env:{var} cannot resolve: environment variable '{var}' IS SET but its \
                     value is not valid UTF-8, so it cannot be read as a secret — this is an \
                     ENCODING problem, not a missing variable; re-export it as UTF-8 (setting it \
                     again will not help)"
                )),
                Ok(v) if v.is_empty() => Err(format!(
                    "secret env:{var} resolved to an EMPTY value; a secret must be non-empty \
                     (fail-closed)"
                )),
                // A BLANK-but-present value is not a credential. `!v.is_empty()` calls "   " a
                // secret, and nothing downstream recovers: `resolve_builtin_string` trims only
                // `['\r', '\n']`, so whitespace survives the string path too and gets sent
                // upstream as a bearer token. The same fail-closed rule that refuses an empty
                // secret has to refuse this one. Only an ENTIRELY-whitespace value is refused —
                // the accepted value is returned byte-for-byte, never trimmed, because trailing
                // bytes are part of the secret for a PEM chain and this is the RAW-bytes path.
                Ok(v) if v.trim().is_empty() => Err(format!(
                    "secret env:{var} resolved to a BLANK value (whitespace only); a secret must \
                     carry actual content, and the variable IS SET — fix its value, not its \
                     presence (fail-closed)"
                )),
                Ok(v) => Ok(v.into_bytes()),
            },
        };
    }
    if let Some(path) = self_file_path_checked(secret)? {
        // A path-shaped source must name a REGULAR FILE. A directory `open()`s fine on Unix and
        // fails only at read time with a bare errno ("Is a directory"), which does not tell an
        // operator they pointed the credential at a folder; a fifo opens and then BLOCKS until a
        // writer appears, hanging boot with no diagnostic at all. `fs::metadata` FOLLOWS symlinks,
        // which is required, not incidental: Kubernetes projects every secret as a symlink into a
        // `..data/` directory, so a check written against `symlink_metadata` would refuse the most
        // common real deployment of a `file:` secret.
        //
        // A metadata error is deliberately NOT handled here — a missing or unreadable path falls
        // through to the read below so it keeps its existing "cannot resolve: <cause>" message.
        // Absent and wrong-type are different operator errors and stay distinguishable.
        if let Ok(md) = std::fs::metadata(&path) {
            if !md.is_file() {
                let kind = if md.is_dir() {
                    "a directory"
                } else {
                    "a device node, socket, or fifo"
                };
                return Err(format!(
                    "secret file:{path} cannot resolve: '{path}' is not a regular file (it is \
                     {kind}); a `file:` secret must name a regular file holding the credential \
                     bytes (fail-closed)"
                ));
            }
        }
        return match read_secret_file_bounded(&path) {
            Ok(bytes) if bytes.is_empty() => Err(format!(
                "secret file:{path} resolved to an EMPTY file; a secret must be non-empty \
                 (fail-closed)"
            )),
            // The `env:` blank rule, applied on the side that needs it in BYTE form. A file of
            // three spaces is present and non-empty and is still not a credential. The test is
            // "every byte is ASCII whitespace", NOT "the bytes decode to a blank string": a binary
            // secret (a DER key, a raw 32-byte token) is frequently not UTF-8 at all, and must keep
            // resolving. Bytes that pass are returned untouched — a PEM chain's trailing newline is
            // part of the secret, so this refuses blankness and never trims content.
            Ok(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => Err(format!(
                "secret file:{path} resolved to a BLANK file (whitespace only); a secret must \
                 carry actual content, and the file DOES exist — fix its contents, not its \
                 presence (fail-closed)"
            )),
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(format!("secret file:{path} cannot resolve: {e}")),
        };
    }
    Err(format!(
        "secret module '{}' is not a built-in (`env` / `file`) and no secret plugin provides it; \
         a secret that cannot resolve is a hard error (fail-closed)",
        secret.module
    ))
}

/// The largest a `file:`-sourced secret is allowed to be. A secret is a credential (an API key, a
/// bearer token, a TLS private key or a short PEM chain, a service-account JSON blob) — never a
/// multi-megabyte payload — so 1 MiB is generous headroom above any realistic secret (a few KiB at
/// most, even a long PEM certificate chain) while still bounding memory: `settings.path` can name
/// any path the process can read (a device node such as `/dev/zero`, a named pipe, an
/// operator-controlled mount), and an unbounded `std::fs::read` would buffer the whole thing before
/// the emptiness/UTF-8 checks ever run, turning a misconfigured or hostile path into an OOM.
const MAX_SECRET_FILE_BYTES: u64 = 1024 * 1024;

/// Read a `file:`-sourced secret with `MAX_SECRET_FILE_BYTES` enforced BEFORE the read buffers the
/// content, not after: `Read::take` caps the reader itself, so a file (or fifo, or device node)
/// larger than the limit never gets fully materialized in memory. A file over the cap is a hard
/// error (fail-closed), never a silent truncation — a truncated credential is worse than a rejected
/// one.
fn read_secret_file_bounded(path: &str) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    // Read one byte PAST the cap: a file of exactly the limit is accepted, and a file one byte
    // over it is provably over, without ever buffering more than `MAX_SECRET_FILE_BYTES + 1` bytes
    // regardless of how large the underlying source actually is.
    let mut limited = (&mut file).take(MAX_SECRET_FILE_BYTES + 1);
    limited.read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_SECRET_FILE_BYTES {
        return Err(std::io::Error::other(format!(
            "file exceeds the {MAX_SECRET_FILE_BYTES}-byte secret size limit"
        )));
    }
    Ok(buf)
}

/// The `env` module's variable name, validating the settings shape (a malformed built-in ref must
/// fail loudly, not fall through to "unknown module").
fn self_env_var_checked(secret: &SecretRef) -> Result<Option<String>, String> {
    if secret.module != SECRET_MODULE_ENV {
        return Ok(None);
    }
    match secret.env_var() {
        Some(v) if !v.trim().is_empty() => Ok(Some(v.to_string())),
        _ => Err(
            "secret module 'env' requires settings.key naming the environment variable \
             (e.g. `{ env: MY_VAR }` or `{ module: env, settings: { key: MY_VAR } }`)"
                .to_string(),
        ),
    }
}

/// The `file` module's path, validating the settings shape.
fn self_file_path_checked(secret: &SecretRef) -> Result<Option<String>, String> {
    if secret.module != SECRET_MODULE_FILE {
        return Ok(None);
    }
    match secret.file_path() {
        Some(p) if !p.trim().is_empty() => Ok(Some(p.to_string())),
        _ => Err(
            "secret module 'file' requires settings.path naming the file \
             (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)"
                .to_string(),
        ),
    }
}

/// The NEUTRAL secret-resolver SEAM an extracted plane names instead of the engine's concrete
/// `SecretResolver`. A plane only needs to turn a [`SecretRef`] into bytes or a UTF-8 string;
/// naming this trait — not the core struct — keeps the plane free of an engine dependency. The
/// engine's `SecretResolver` implements it (delegating to its own resolution), and `EngineHost`
/// hands the plane an `Arc<dyn SecretResolve>` snapshot.
///
/// FAIL-CLOSED, exactly as the underlying resolver: an unknown module, an unset source, or an empty
/// value is an `Err(String)`, never an empty secret. The error is a neutral `String` — a plane never
/// sees an engine-only error type across this seam.
pub trait SecretResolve: Send + Sync {
    /// Resolve a reference to raw bytes (fail-closed). Some consumers — a raw-file loader, for
    /// instance — need the untrimmed bytes rather than a string.
    fn resolve(&self, secret: &SecretRef) -> Result<Vec<u8>, String>;

    /// Resolve a reference to a UTF-8 STRING (trailing newline trimmed; fail-closed on non-UTF-8 or
    /// empty). Some consumers — a credential-minting path, for instance — need the string form.
    fn resolve_string(&self, secret: &SecretRef) -> Result<String, String>;
}

/// Resolve a secret reference to a UTF-8 STRING (trailing newline trimmed - the universal
/// file-delivered-secret convention). Fail-closed on non-UTF-8.
pub fn resolve_builtin_string(secret: &SecretRef) -> Result<String, String> {
    let bytes = resolve_builtin(secret)?;
    let s = String::from_utf8(bytes).map_err(|_| {
        format!(
            "secret {} resolved to non-UTF-8 bytes where a text secret is required",
            secret.describe()
        )
    })?;
    let trimmed = s.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err(format!(
            "secret {} resolved to an empty value after trimming trailing newlines (fail-closed)",
            secret.describe()
        ));
    }
    Ok(trimmed.to_string())
}
