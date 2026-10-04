// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `open_outbound`'s body for `sigv4`: bind the style to its credential and settings
//! ([`open_binding`]). Never touches the network. The per-request presentation, both credential
//! modes, is [`crate::signing::SigV4Binding::sign`] through [`crate::Fields`].
//!
//! THE SETTINGS SCHEMA (ARCHITECT ruling 2026-09-28): `{service, region, content_type}`.
//!
//! THE REFUSALS (ARCHITECT ruling 2026-09-28): a binding that cannot open answers FAILED with one
//! line per finding, each `credential: <text>` or `settings: <text>`. The kernel composes the 1.5.5
//! sentence — `provider '<p>' <style> credential (from <src>) is invalid: <text>`, or
//! `provider '<p>' <text>` — so every `<text>` below is 1.5.5's own words.

use serde_json::{Map, Value};

use crate::signing::{SigV4Binding, SigV4Params, SigningCredential};

/// AWS Signature Version 4.
pub const SIGV4: &str = "sigv4";

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

/// A signing credential an open could not present: its session token is not a legal header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenNote {
    /// A signing credential's session token is not a legal header value; naming the service.
    SessionToken(String),
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

/// A non-blank string setting.
fn text(m: &Map<String, Value>, key: &str) -> Result<Option<String>, Refusal> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.clone())),
        Some(Value::String(_)) => Ok(None),
        Some(_) => Err(Refusal::Settings(format!(
            "outbound auth setting `{key}` is invalid: expected a string"
        ))),
    }
}

fn sigv4_params(m: &Map<String, Value>) -> Result<SigV4Params, Refusal> {
    let missing = |k: &str| Refusal::Settings(format!("uses auth: sigv4 but has no `{k}`"));
    Ok(SigV4Params {
        service: text(m, "service")?.ok_or_else(|| missing("service"))?,
        region: text(m, "region")?.ok_or_else(|| missing("region"))?,
        content_type: text(m, "content_type")?.ok_or_else(|| missing("content_type"))?,
    })
}

/// Bind `style` (`sigv4`) to `credential` under `settings` — `open_outbound`'s body.
///
/// # Errors
///
/// Every finding that refuses the binding, in 1.5.5's check order.
pub fn open_binding(
    style: &str,
    credential: Option<&[u8]>,
    settings: Option<&[u8]>,
    notes: &mut Vec<OpenNote>,
) -> Result<SigV4Binding, Vec<Refusal>> {
    if style != SIGV4 {
        return Err(vec![Refusal::Settings(format!(
            "outbound auth style `{style}` is not served by this plugin"
        ))]);
    }
    let m = object(settings).map_err(|r| vec![r])?;
    let params = sigv4_params(&m).map_err(|r| vec![r])?;
    let credential_text = match credential.map(std::str::from_utf8) {
        None => None,
        Some(Ok(s)) => Some(s),
        Some(Err(_)) => {
            return Err(vec![Refusal::Credential(
                "the credential is not UTF-8".to_string(),
            )])
        }
    };
    let cred = credential_text.and_then(SigningCredential::split);
    if cred
        .as_ref()
        .is_some_and(SigningCredential::session_token_unsendable)
    {
        notes.push(OpenNote::SessionToken(params.service.clone()));
    }
    Ok(SigV4Binding::new(params, cred))
}

#[cfg(test)]
#[path = "tests/style_tests.rs"]
mod tests;
