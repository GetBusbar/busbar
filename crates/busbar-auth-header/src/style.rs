// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STYLES AND THEIR BINDINGS: `open_outbound` binds one style to its credential and settings
//! ([`open_binding`]); the per-request call presents through the binding ([`Binding`]) in either
//! credential mode — the operator's own, or the caller's verified credential
//! ([`Binding::passthrough`], [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]).
//!
//! THE SETTINGS SCHEMA (ARCHITECT ruling 2026-09-28): the kernel resolves the dialect's declared
//! parameters at seal into `OpenOutboundIn::settings`, a JSON object whose shape per style is:
//!
//! | style | settings |
//! |---|---|
//! | `bearer` | `{families?, own?, passthrough?}` (default: `Bearer` whatever the credential) |
//! | `api-key` | `{header?: "api-key", families?, own?, passthrough?}` |
//! | `x-goog-api-key` | `{header?: "x-goog-api-key", families?, own?, passthrough?}` |
//! | `query-key` | `{param?: "key"}` (the dialect's default parameter name) |
//!
//! `families` is a dialect's credential-family table, `[{prefix, header?, trim_start?}]` (a row
//! without `header` presents as a bearer); `own` / `passthrough` are `{header?, trim_start?}`.
//!
//! THE REFUSALS (ARCHITECT ruling 2026-09-28): a binding that cannot open answers FAILED with one
//! line per finding, each `credential: <text>` or `settings: <text>`. The kernel composes the 1.5.5
//! sentence — `provider '<p>' <style> credential (from <src>) is invalid: <text>`, or
//! `provider '<p>' <text>` — so every `<text>` below is 1.5.5's own words.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::present::{Family, Mode, Presentation, StaticScheme};

/// `authorization: Bearer <credential>`.
pub const BEARER: &str = "bearer";
/// The credential verbatim in a custom header (`api-key` unless the settings name another).
pub const API_KEY: &str = "api-key";
/// The credential verbatim in `x-goog-api-key`.
pub const X_GOOG_API_KEY: &str = "x-goog-api-key";
/// The credential verbatim as a QUERY PARAMETER on the request target (`?key=<credential>` unless
/// the settings name another `param`), never a header: its fields carry
/// [`FIELD_QUERY`](busbar_contract::abi::auth::FIELD_QUERY).
pub const QUERY_KEY: &str = "query-key";
/// The query parameter [`QUERY_KEY`] presents under when the settings name none.
pub const QUERY_KEY_DEFAULT_PARAM: &str = "key";

/// One finding that refuses a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The credential is invalid: the kernel wraps it in `<style> credential (from <src>) is
    /// invalid:`.
    Credential(String),
    /// The settings are: the kernel prefixes `provider '<p>' `.
    Settings(String),
}

impl Refusal {
    /// The line `open_outbound` answers.
    pub fn line(&self) -> String {
        match self {
            Refusal::Credential(t) => format!("credential: {t}"),
            Refusal::Settings(t) => format!("settings: {t}"),
        }
    }
}

/// A credential an open could not present for bytes invalid in a header value, as the diagnostic
/// it raises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenNote {
    /// A static header omitted for invalid bytes (`EGRESS_APIKEY_INVALID_BYTES`), naming the header.
    Header(String),
    /// A bearer omitted for invalid bytes (`PROTO_AUTH_INVALID_HEADER_BYTES`).
    Bearer,
    /// A credential-family table's credential omitted for invalid bytes, naming the header.
    Family(String),
}

/// One open binding: the scheme, and the fields its own credential presents, built once.
#[derive(Debug)]
pub struct Binding {
    scheme: StaticScheme,
    own: Vec<(String, String)>,
    query: bool,
}

impl Binding {
    /// Whether this binding's fields are query parameters ([`QUERY_KEY`]), not headers.
    pub fn query(&self) -> bool {
        self.query
    }

    /// The fields the binding's own credential presents (empty: no header) — [`Mode::Own`].
    pub fn own(&self) -> &[(String, String)] {
        &self.own
    }

    /// The fields a caller's credential presents — [`Mode::Passthrough`].
    pub fn passthrough(&self, credential: &str) -> Vec<(String, String)> {
        if credential.is_empty() {
            return Vec::new();
        }
        self.scheme.present(credential, Mode::Passthrough)
    }
}

/// The settings object (`{}` when absent).
fn object(settings: Option<&[u8]>) -> Result<Map<String, Value>, Refusal> {
    let Some(bytes) = settings.filter(|b| !b.is_empty()) else {
        return Ok(Map::new());
    };
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(Refusal::Settings(
            "outbound auth settings must be a JSON object".to_string(),
        )),
        Err(e) => Err(Refusal::Settings(format!(
            "outbound auth settings are not JSON: {e}"
        ))),
    }
}

fn field<T: for<'de> Deserialize<'de>>(
    m: &Map<String, Value>,
    key: &str,
) -> Result<Option<T>, Refusal> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => serde_json::from_value(v.clone()).map(Some).map_err(|e| {
            Refusal::Settings(format!("outbound auth setting `{key}` is invalid: {e}"))
        }),
    }
}

/// A non-blank string setting.
fn text(m: &Map<String, Value>, key: &str) -> Result<Option<String>, Refusal> {
    Ok(field::<String>(m, key)?.filter(|s| !s.trim().is_empty()))
}

/// A style's scheme: its default presentation, overridden by the settings.
fn static_scheme(style: &str, m: &Map<String, Value>) -> Result<StaticScheme, Refusal> {
    if style == QUERY_KEY {
        // One parameter, the credential verbatim; the header settings do not apply to it.
        let param = text(m, "param")?;
        return Ok(StaticScheme::uniform(Presentation::raw(
            param.as_deref().unwrap_or(QUERY_KEY_DEFAULT_PARAM),
        )));
    }
    let default = match style {
        BEARER => Presentation::BEARER,
        API_KEY => Presentation::raw(text(m, "header")?.as_deref().unwrap_or(API_KEY)),
        X_GOOG_API_KEY => {
            Presentation::raw(text(m, "header")?.as_deref().unwrap_or(X_GOOG_API_KEY))
        }
        other => {
            return Err(Refusal::Settings(format!(
                "outbound auth style `{other}` is not served by this plugin"
            )))
        }
    };
    let mut scheme = StaticScheme::uniform(default);
    if let Some(families) = field::<Vec<Family>>(m, "families")? {
        scheme.families = families;
    }
    if let Some(own) = field::<Presentation>(m, "own")? {
        scheme.own = own;
    }
    if let Some(passthrough) = field::<Presentation>(m, "passthrough")? {
        scheme.passthrough = passthrough;
    }
    Ok(scheme)
}

/// The note for a credential a static scheme could not present, in the line its builder logged.
fn unpresented(scheme: &StaticScheme, credential: &str, mode: Mode) -> OpenNote {
    let p = scheme.presentation(credential, mode);
    let header = p
        .header
        .clone()
        .unwrap_or_else(|| "authorization".to_string());
    if !scheme.families.is_empty() {
        OpenNote::Family(header)
    } else if p.header.is_some() {
        OpenNote::Header(header)
    } else {
        OpenNote::Bearer
    }
}

/// Bind `style` to `credential` under `settings` — `open_outbound`'s body. Never touches the
/// network.
///
/// # Errors
///
/// Every finding that refuses the binding, in 1.5.5's check order.
pub fn open_binding(
    style: &str,
    credential: Option<&[u8]>,
    settings: Option<&[u8]>,
    notes: &mut Vec<OpenNote>,
) -> Result<Binding, Vec<Refusal>> {
    let m = object(settings).map_err(|r| vec![r])?;
    let credential_text = match credential.map(std::str::from_utf8) {
        None => None,
        Some(Ok(s)) => Some(s),
        Some(Err(_)) => {
            return Err(vec![Refusal::Credential(
                "the credential is not UTF-8".to_string(),
            )])
        }
    };
    let scheme = static_scheme(style, &m).map_err(|r| vec![r])?;
    // NO CREDENTIAL ⇒ NO AUTH HEADER (1.5.5's `prebuild_auth`): an empty key is a keyless upstream
    // (`api_key: none`), and an empty `Authorization: Bearer ` is strictly worse than nothing.
    let credential_text = credential_text.unwrap_or("");
    let own = if credential_text.is_empty() {
        Vec::new()
    } else {
        scheme.present(credential_text, Mode::Own)
    };
    if !credential_text.is_empty() && own.is_empty() {
        notes.push(unpresented(&scheme, credential_text, Mode::Own));
    }
    Ok(Binding {
        scheme,
        own,
        query: style == QUERY_KEY,
    })
}

#[cfg(test)]
#[path = "tests/style_tests.rs"]
mod tests;
