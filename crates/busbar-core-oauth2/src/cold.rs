// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate's one cold module: refusal and failure text the request path (`routes`, `shared`,
//! `plane::serve`) needs only when something went wrong. Out of line and rare.

use oauth_as::store::StorageError;

/// A store operation that failed, named with what it was doing.
#[cold]
#[inline(never)]
pub(crate) fn store_failed(what: &str, f: impl std::fmt::Debug) -> StorageError {
    StorageError::new(format!("oauth_as store: {what}: {f:?}"))
}

/// A store record that did not decode, named with what it was.
#[cold]
#[inline(never)]
pub(crate) fn store_decode_failed(what: &str, e: &serde_json::Error) -> StorageError {
    StorageError::new(format!("oauth_as store: {what} did not decode: {e}"))
}

/// A form component whose percent-escapes decoded to bytes that are not UTF-8: replaced.
#[cold]
#[inline(never)]
pub(crate) fn lossy_form_component(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The page that shows an authorization refusal the server answered as JSON: its error code (or
/// the HTTP status when it names none) and its description, escaped.
#[cold]
#[inline(never)]
pub(crate) fn authorization_error_page(status: http::StatusCode, body: &[u8]) -> String {
    let error: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let code = error["error"]
        .as_str()
        .map_or_else(|| format!("HTTP {}", status.as_u16()), str::to_string);
    let description = error["error_description"].as_str().unwrap_or_default();
    format!(
        "<!doctype html><meta charset=utf-8><title>busbar — authorization error</title>\
         <h1>Authorization error</h1>\
         <p>error: <code>{code}</code></p>\
         <p>{description}</p>",
        code = super::routes::Escaped(&code),
        description = super::routes::Escaped(description),
    )
}

/// A swap that lost every one of its attempts to a concurrent writer.
#[cold]
#[inline(never)]
pub(crate) fn no_version_won(kind_name: &str, attempts: u32) -> StorageError {
    StorageError::new(format!(
        "oauth_as store: {kind_name}: no version won in {attempts} attempts"
    ))
}

/// A signing key the store lost between the write and the read that follows it.
#[cold]
#[inline(never)]
pub(crate) fn signing_key_not_kept() -> String {
    "the store did not keep the signing key".to_string()
}
