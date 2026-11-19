// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One `upstreams.<name>` entry typed into an [`UpstreamDef`] (IF §12.1, §12.18 upstream bindings).
//!
//! The entry is core config: an operator writes it, and a 1.5.x plane's `migrate` hands its members over as
//! CORE_CFG(UPSTREAM) fragments in the same grammar (§12.10). The `auth` and `upstream_credentials` keys are the
//! config grammar's ([`UpstreamCfg`], W1-K7); this module types the rest and applies the rules that moved to core
//! with the stdio command (plane-mcp tools_config.rs `validate_endpoint`/`validate_local_program`):
//!
//! ```yaml
//! upstreams:
//!   <name>:
//!     url: https://agent.example/a2a          # a network upstream, or
//!     command:                                # a stdio upstream core spawns
//!       argv: [/opt/mcp/server, --flag]       # argv[0] absolute, never resolved through PATH
//!       env: {API_KEY: <secret ref>}          # resolved through custody at spawn
//!       cwd: /srv/mcp                         # absolute; absent = inherit busbar's
//!       pin: {mechanism: local_program, key: /opt/mcp/server}   # or {mechanism: unpinned}; absent = unpinned
//!       idle_s: 300
//!     tls:                                    # network upstreams over https:// only
//!       pin_spki: [sha256:<64 hex>]           # any match passes
//!       client_identity: <secret ref>         # PEM chain + key presented as the client certificate
//!       trust: <PEM>                          # an operator CA for this upstream only
//!     auth: ...                               # config grammar (W1-K7), resolved by W1-K6
//!     upstream_credentials: ...               # config grammar (W1-K7), checked by W1-K6
//! ```
//!
//! Every refusal is core text naming `upstreams.<name>` and the key, and never repeats a URL's userinfo or a
//! secret value (URLs are shown through `abi::host::scrub::mask_url`).

use std::path::Path;
use std::sync::Arc;

use busbar_contract::secret_ref::SecretRef;
use busbar_plugin_abi::host_side::scrub::mask_url;

use busbar_contract::json::{self, JsonContainerTrait as _, JsonValueTrait as _, Map, Value};

use super::{ProgramPin, StdioCommand, UpstreamAuth, UpstreamDef, UpstreamTls};
use crate::config::min3::{UpstreamAuthCfg, UpstreamAuthForm, UpstreamCfg};
use crate::plugin_config::TrustAnchor;

/// A stdio child's idle time before core closes it, when `command.idle_s` is absent (IF §12.4 channels).
pub const DEFAULT_IDLE_S: u64 = 300;
/// The longest upstream name: the CORE_CFG name grammar `[a-z0-9_.-]{1,64}` (§3 `CoreCfgRec`).
pub const MAX_NAME: usize = 64;

const KEYS: &[&str] = &[
    "url",
    "command",
    "tls",
    "auth",
    "upstream_credentials",
    "allow_private",
    "resource",
];
const COMMAND_KEYS: &[&str] = &["argv", "env", "cwd", "pin", "idle_s"];
const TLS_KEYS: &[&str] = &["pin_spki", "client_identity", "trust"];
const PIN_KEYS: &[&str] = &["mechanism", "key"];

/// The implicit outbound auth instance W1-K6 opens for an upstream whose `auth` is a core-vocabulary form
/// (`auth.upstream-<name>-outbound`, §12.18): its configured name.
pub fn implicit_instance(upstream: &str) -> Box<str> {
    format!("upstream-{upstream}-outbound").into()
}

impl UpstreamDef {
    /// Types the `upstreams.<name>` entry `entry` over the keys the config grammar parsed for it (`cfg`).
    /// `anchor` decodes a `tls.trust` PEM bundle into the anchor the connector adds to this upstream's roots (the
    /// binder's decoder, IF §12.7; its error text must not repeat the PEM). Err = every refusal of the entry.
    pub fn from_config(
        name: &str,
        entry: &Value,
        cfg: &UpstreamCfg,
        anchor: &dyn Fn(&str) -> Result<Arc<TrustAnchor>, String>,
    ) -> Result<Self, Vec<String>> {
        Self::from_config_at(name, &format!("upstreams.{name}"), entry, cfg, anchor)
    }

    /// Types an entry with a caller-supplied instance/registration path for safe refusal diagnostics.
    pub fn from_config_at(
        name: &str,
        diagnostic_path: &str,
        entry: &Value,
        cfg: &UpstreamCfg,
        anchor: &dyn Fn(&str) -> Result<Arc<TrustAnchor>, String>,
    ) -> Result<Self, Vec<String>> {
        let at = format!("`{diagnostic_path}`");

        let mut refused = Vec::new();
        if !valid_name(name) {
            refused.push(format!(
                "{at}: an upstream name is 1 to {MAX_NAME} of `a-z`, `0-9`, `_`, `.` and `-`"
            ));
        }
        let Some(map) = entry.as_object() else {
            refused.push(format!(
                "{at} must be a map naming `url:` or `command:`, with optional `tls:`, `auth:` and \
                 `upstream_credentials:`"
            ));
            return Err(refused);
        };
        unknown_keys(&at, "", map, KEYS, &mut refused);

        let allow_private = match map.get(&"allow_private") {
            None => false,
            Some(value) => match value.as_bool() {
                Some(value) => value,
                None => {
                    refused.push(format!("{at}: `allow_private` must be a boolean"));
                    false
                }
            },
        };

        let url_given = given(map, "url");
        let command_given = given(map, "command");
        match (url_given, command_given) {
            (false, false) => refused.push(format!(
                "{at} needs `url:` (an upstream reached over the network) or `command:` (a program busbar \
                 spawns and talks to over stdio)"
            )),
            (true, true) => refused.push(format!(
                "{at}: `url:` and `command:` name two different servers (one reached over the network, one \
                 spawned over stdio); drop one"
            )),
            _ => {}
        }
        let url = map
            .get(&"url")
            .filter(|v| !v.is_null())
            .and_then(|v| url(&at, v, &mut refused));
        let command = map
            .get(&"command")
            .filter(|v| !v.is_null())
            .and_then(|v| command(&at, v, &mut refused));
        let tls_given = given(map, "tls");
        let tls = match map.get(&"tls").filter(|v| !v.is_null()) {
            Some(v) => tls(&at, v, anchor, &mut refused),
            None => no_tls(),
        };

        if command_given {
            stdio_refusals(&at, map, cfg, tls_given, &mut refused);
            if map.contains_key(&"allow_private") {
                refused.push(format!(
                    "{at}: `allow_private` is inapplicable to a stdio upstream (`command:`)"
                ));
            }
        } else if let Some(url) = url.as_deref() {
            if is_plain_http(url) {
                for (key, set) in [
                    ("pin_spki", !tls.pin_spki.is_empty()),
                    ("client_identity", tls.client_identity.is_some()),
                    ("trust", tls.trust.is_some()),
                ] {
                    if set {
                        refused.push(format!(
                            "{at}: `tls.{key}` needs a TLS handshake, and `url:` is `http://`, which has none; \
                             name an `https://` endpoint or drop `tls.{key}`"
                        ));
                    }
                }
            }
        }

        let auth = cfg
            .auth
            .as_ref()
            .map(|auth| UpstreamAuth::from_config(name, auth));
        if !refused.is_empty() {
            return Err(refused);
        }
        Ok(UpstreamDef {
            name: name.into(),
            resource: cfg.resource.clone(),
            url,
            command,
            tls,
            auth,
            allow_private,
        })
    }
}

impl UpstreamAuth {
    /// The binding `upstreams.<name>.auth` names, before W1-K6 resolves it (§12.18): `instance` is the operator's
    /// auth instance, or [`implicit_instance`] for a core-vocabulary form; `connect_callback` is the URL path of a
    /// `connection` form's `redirect_uri`. `caller`, `scoped` and `per_request` start false: K6 derives them from
    /// the binding's style flags (`Registry::style_flags`), never from the plane.
    pub fn from_config(upstream: &str, cfg: &UpstreamAuthCfg) -> Self {
        let instance = match &cfg.form {
            UpstreamAuthForm::Instance(name) => name.clone(),
            _ => implicit_instance(upstream),
        };
        let connect_callback = match &cfg.form {
            UpstreamAuthForm::Connection { redirect_uri, .. } => Some(url_path(redirect_uri)),
            _ => None,
        };
        UpstreamAuth {
            instance,
            cache_max_s: cfg.cache_max_s,
            connect_callback,
            caller: false,
            scoped: false,
            per_request: false,
        }
    }
}

/// `[a-z0-9_.-]{1,64}`.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
}

/// The key is present with a value (an explicit `null` is absent).
fn given(map: &Map, key: &str) -> bool {
    map.get(&key).is_some_and(|v| !v.is_null())
}

fn unknown_keys(at: &str, prefix: &str, map: &Map, known: &[&str], refused: &mut Vec<String>) {
    for (key, _) in map {
        if !known.contains(&key) {
            refused.push(format!(
                "{at}: `{prefix}{key}` is not an upstream key; the keys are {}",
                known
                    .iter()
                    .map(|k| format!("`{prefix}{k}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
}

/// The URL path of `url` (no query, no fragment); `/` when the URL names none.
fn url_path(url: &str) -> Box<str> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path_at = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let path = &rest[path_at..];
    let path = &path[..path.find(['?', '#']).unwrap_or(path.len())];
    if path.is_empty() {
        "/".into()
    } else {
        path.into()
    }
}

/// Whether `url` names an endpoint reached without TLS: `http://`, or `ws://` (a WebSocket far end, the upgrade
/// of an `http://` connection).
fn is_plain_http(url: &str) -> bool {
    url.split_once("://").is_some_and(|(scheme, _)| {
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("ws")
    })
}

/// The schemes an upstream's `url:` may name: HTTP, and the WebSocket far end of an upgraded session (a
/// Realtime provider), each plain or over TLS. Which transport carries each is core's scheme table
/// (`native_dial::locate`), and a scheme whose carrier the deployment does not supply is refused there.
const URL_SCHEMES: [&str; 4] = ["https", "http", "wss", "ws"];

fn url(at: &str, value: &Value, refused: &mut Vec<String>) -> Option<Box<str>> {
    let Some(url) = value.as_str() else {
        refused.push(format!(
            "{at}: `url:` must be a string naming the upstream's endpoint"
        ));
        return None;
    };
    let shown = mask_url(url);
    if url.trim() != url || url.is_empty() {
        refused.push(format!(
            "{at}: `url:` is empty or has leading or trailing whitespace; write the exact endpoint"
        ));
        return None;
    }
    if url.chars().any(char::is_control) || url.contains(' ') {
        refused.push(format!(
            "{at}: `url: {shown}` contains whitespace or a control character"
        ));
        return None;
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        refused.push(format!(
            "{at}: `url: {shown}` must be an `http://` or `https://` endpoint"
        ));
        return None;
    };
    if !(scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http")) {
        refused.push(format!(
            "{at}: `url: {shown}` must be an `http://` or `https://` endpoint"
        ));
        return None;
    }
    let authority = &rest[..rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len())];
    if authority.contains('@') {
        refused.push(format!(
            "{at}: `url: {shown}` carries userinfo; an upstream's credential goes in `upstreams.<name>.auth`, \
             never in its URL"
        ));
        return None;
    }
    if authority.is_empty() || authority.starts_with(':') {
        refused.push(format!("{at}: `url: {shown}` names no host"));
        return None;
    }
    Some(url.into())
}

/// An absolute path with no padding and no NUL; Err = what is wrong with it.
fn absolute_path(path: &str) -> Result<(), &'static str> {
    if path.contains('\0') {
        return Err("contains a NUL byte");
    }
    if path.trim() != path || path.is_empty() {
        return Err("is empty or has leading or trailing whitespace");
    }
    if !Path::new(path).is_absolute() {
        return Err("must be an ABSOLUTE path");
    }
    Ok(())
}

fn command(at: &str, value: &Value, refused: &mut Vec<String>) -> Option<StdioCommand> {
    let Some(map) = value.as_object() else {
        refused.push(format!(
            "{at}: `command:` must be a map with `argv:` and optional `env:`, `cwd:`, `pin:` and `idle_s:`"
        ));
        return None;
    };
    let before = refused.len();
    unknown_keys(at, "command.", map, COMMAND_KEYS, refused);

    let argv: Vec<Box<str>> = match map.get(&"argv") {
        Some(value) if value.as_array().is_some_and(|items| !items.is_empty()) => {
            let items = value.as_array().expect("array guard");
            let mut argv = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                match item.as_str() {
                    Some(arg) if arg.contains('\0') => refused.push(format!(
                        "{at}: `command.argv[{i}]` contains a NUL byte, which no program argument can carry"
                    )),
                    Some(arg) => argv.push(arg.into()),
                    None => refused.push(format!("{at}: `command.argv[{i}]` must be a string")),
                }
            }
            argv
        }
        _ => {
            refused.push(format!(
                "{at}: `command.argv:` must list the program busbar spawns, its absolute path first. There is \
                 no default and busbar will not guess one."
            ));
            Vec::new()
        }
    };
    if let Some(program) = argv.first() {
        if let Err(why) = absolute_path(program) {
            refused.push(format!(
                "{at}: `command.argv[0]` {why}. A bare name is resolved through `PATH`, which would let \
                 whoever controls busbar's environment choose the binary that runs instead of you."
            ));
        }
    }

    let mut env = Vec::new();
    match map.get(&"env") {
        None => {}
        Some(value) if value.is_null() => {}
        Some(value) if value.is_object() => {
            let vars = value.as_object().expect("object guard");
            for (var, reference) in vars {
                if var.is_empty() || var.contains('=') || var.contains('\0') {
                    refused.push(format!(
                        "{at}: `command.env` name `{var}` is not a usable environment variable name: it must be \
                         non-empty and contain neither `=` nor a NUL byte"
                    ));
                    continue;
                }
                match json::from_value::<SecretRef>(reference) {
                    Ok(reference) => env.push((var.into(), reference)),
                    Err(e) => refused.push(format!(
                        "{at}: `command.env.{var}` must be a secret reference: {e}"
                    )),
                }
            }
        }
        Some(_) => refused.push(format!(
            "{at}: `command.env:` must be a map of variable name to secret reference"
        )),
    }

    let cwd: Option<Box<str>> = match map.get(&"cwd") {
        None => None,
        Some(value) if value.is_null() => None,
        Some(value) if value.is_str() => {
            let dir = value.as_str().expect("string guard");
            if let Err(why) = absolute_path(dir) {
                refused.push(format!(
                    "{at}: `command.cwd: {dir}` {why}; a relative one is resolved against whatever directory \
                     busbar was started in, which is not a thing this file can see"
                ));
            }
            Some(dir.into())
        }
        Some(_) => {
            refused.push(format!("{at}: `command.cwd:` must be a string"));
            None
        }
    };

    let pin = pin(
        at,
        map.get(&"pin"),
        argv.first().map(|p| &**p),
        cwd.as_deref(),
        refused,
    );

    let idle_s = match map.get(&"idle_s") {
        None => DEFAULT_IDLE_S,
        Some(value) if value.is_null() => DEFAULT_IDLE_S,
        Some(v) => match v.as_u64() {
            Some(s) if s > 0 => s,
            _ => {
                refused.push(format!(
                    "{at}: `command.idle_s:` must be a whole number of seconds above 0 (default {DEFAULT_IDLE_S})"
                ));
                DEFAULT_IDLE_S
            }
        },
    };

    if refused.len() != before {
        return None;
    }
    Some(StdioCommand {
        argv,
        env,
        cwd,
        pin: pin?,
        idle_s,
    })
}

/// `command.pin`: absent or `unpinned` = no approval claim; `local_program` = today's plane-mcp rules, enforced by
/// core (tools_config.rs `validate_local_program`): `key` is exactly `argv[0]` and `cwd` is explicit and absolute.
fn pin(
    at: &str,
    value: Option<&Value>,
    program: Option<&str>,
    cwd: Option<&str>,
    refused: &mut Vec<String>,
) -> Option<ProgramPin> {
    let map = match value {
        None => return Some(ProgramPin::Unpinned),
        Some(value) if value.is_null() => return Some(ProgramPin::Unpinned),
        Some(value) if value.is_object() => value.as_object().expect("object guard"),
        Some(_) => {
            refused.push(format!(
                "{at}: `command.pin:` must be a map with `mechanism:` (`local_program` or `unpinned`)"
            ));
            return None;
        }
    };
    unknown_keys(at, "command.pin.", map, PIN_KEYS, refused);
    let key = map.get(&"key").filter(|v| !v.is_null());
    match map.get(&"mechanism").and_then(Value::as_str) {
        Some("unpinned") => {
            if key.is_some() {
                refused.push(format!(
                    "{at}: `command.pin.key` has no meaning under `mechanism: unpinned`; drop it, or use \
                     `local_program`"
                ));
                return None;
            }
            Some(ProgramPin::Unpinned)
        }
        Some("local_program") => {
            let key = key.and_then(Value::as_str);
            let Some(key) = key.filter(|key| !key.contains('\0') && Some(*key) == program) else {
                refused.push(format!(
                    "{at}: `local_program` needs `command.pin.key:` equal to the exact configured absolute \
                     `command.argv[0]` path; it is not an executable or environment digest"
                ));
                return None;
            };
            if cwd.is_none_or(|cwd| absolute_path(cwd).is_err()) {
                refused.push(format!(
                    "{at}: `local_program` needs an explicit absolute `command.cwd:` without NUL bytes, which \
                     core applies at spawn"
                ));
                return None;
            }
            Some(ProgramPin::LocalProgram { key: key.into() })
        }
        Some(mechanism @ ("cert_spki" | "mtls")) => {
            refused.push(format!(
                "{at}: `command.pin.mechanism: {mechanism}` authenticates a TLS connection, and a stdio program \
                 has none; use `local_program` or `unpinned`"
            ));
            None
        }
        _ => {
            refused.push(format!(
                "{at}: `command.pin.mechanism:` must be `local_program` or `unpinned`"
            ));
            None
        }
    }
}

fn no_tls() -> UpstreamTls {
    UpstreamTls {
        pin_spki: Vec::new(),
        client_identity: None,
        trust: None,
    }
}

fn tls(
    at: &str,
    value: &Value,
    anchor: &dyn Fn(&str) -> Result<Arc<TrustAnchor>, String>,
    refused: &mut Vec<String>,
) -> UpstreamTls {
    let mut tls = no_tls();
    let Some(map) = value.as_object() else {
        refused.push(format!(
            "{at}: `tls:` must be a map with `pin_spki:`, `client_identity:` or `trust:`"
        ));
        return tls;
    };
    unknown_keys(at, "tls.", map, TLS_KEYS, refused);
    match map.get(&"pin_spki") {
        None => {}
        Some(value) if value.is_null() => {}
        Some(value) if value.is_array() => {
            let pins = value.as_array().expect("array guard");
            for (i, pin) in pins.iter().enumerate() {
                match pin.as_str().and_then(spki_digest) {
                    Some(digest) if !tls.pin_spki.contains(&digest) => tls.pin_spki.push(digest),
                    Some(_) => {}
                    None => refused.push(format!(
                        "{at}: `tls.pin_spki[{i}]` is not a SHA-256 SubjectPublicKeyInfo digest; write 64 hex \
                         digits, optionally prefixed `sha256:`"
                    )),
                }
            }
        }
        Some(_) => refused.push(format!(
            "{at}: `tls.pin_spki:` must be a list of SHA-256 digests"
        )),
    }
    match map.get(&"client_identity") {
        None => {}
        Some(value) if value.is_null() => {}
        Some(reference) => match json::from_value::<SecretRef>(reference) {
            Ok(SecretRef::None) => {}
            Ok(reference) => tls.client_identity = Some(reference),
            Err(e) => refused.push(format!(
                "{at}: `tls.client_identity:` must be a secret reference: {e}"
            )),
        },
    }
    match map.get(&"trust") {
        None => {}
        Some(value) if value.is_null() => {}
        Some(value) if value.as_str().is_some_and(|pem| !pem.trim().is_empty()) => {
            match anchor(value.as_str().expect("string guard")) {
                Ok(trust) => tls.trust = Some(trust),
                Err(e) => refused.push(format!("{at}: `tls.trust:` {e}")),
            }
        }
        Some(_) => refused.push(format!(
            "{at}: `tls.trust:` must be a non-empty PEM certificate bundle"
        )),
    }
    tls
}

/// `sha256:<64 hex>` or `<64 hex>`, either case.
fn spki_digest(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_prefix("sha256:").unwrap_or(text).as_bytes();
    if hex.len() != 64 {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(hex.as_chunks::<2>().0) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// The stdio refusals (§12.18, round 21: today's plane-mcp texts, now core's): a pipe has no header block, no
/// handshake and no network hop, so `auth`, `upstream_credentials` and `tls` have nothing to act on.
fn stdio_refusals(
    at: &str,
    map: &Map,
    cfg: &UpstreamCfg,
    tls_given: bool,
    refused: &mut Vec<String>,
) {
    if cfg.auth.is_some() || given(map, "auth") {
        refused.push(format!(
            "{at}: `auth:` has no carrier on a stdio upstream (`command:`): a pipe has no header block to put \
             a credential in. Give the program its credential through `command.env:`, which is the channel a \
             child process actually reads one from."
        ));
    }
    if cfg.upstream_credentials.is_some() || given(map, "upstream_credentials") {
        refused.push(format!(
            "{at}: `upstream_credentials:` selects how busbar credentials a NETWORK hop, and a stdio upstream \
             (`command:`) makes none. A child process's credential belongs in `command.env:`."
        ));
    }
    if tls_given {
        refused.push(format!(
            "{at}: `tls:` cannot be used on a stdio upstream (`command:`), which has no TLS handshake"
        ));
    }
}
