// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`busbar-export-otlp`** — the OTLP trace sink as a `kind: export` plugin (owner ruling Q75,
//! 2026-09-25: OTLP export never delivered in 1.5.5, and 1.6.0 fixes it): `export.<name>.module:
//! otlp`.
//!
//! **What it carries.** The `traces` stream: one record per closed span, built by the host's traces
//! producer (K9a S7) — the span's `trace_id`, `span_id`, `parent_span_id`, `name`, `start`,
//! `duration_us` and whichever of `pool` / `ingress` / `op` / `lane` / `provider` / `model` it
//! carries. Each batch the host hands it becomes one OTLP/HTTP protobuf `ExportTraceServiceRequest`
//! ([`proto`]): one resource (`service.name = busbar`), one scope (`busbar`), one span per record.
//!
//! **Who dials.** The HOST: the sink declares one outbound need ([`door::STATEMENT`]) — framed
//! `http`, pinned to the instance's `url` setting with the userinfo stripped, under the
//! `loopback-allowed` egress class (`https://`, or plaintext `http://` to a loopback collector
//! only) — and a delivery is one
//! `exchange()` over it: `POST`, `content-type: application/x-protobuf`. The sink never dials.
//! Credentials the operator embedded in the URL (`https://user:pass@collector/…`) never ride the
//! request: they move into an `Authorization: Basic` header, and every line this sink writes masks
//! them. A delivery is fire-and-forget and never retried; a refused, failed or non-2xx export drops
//! that batch, logged at debug.
//!
//! **Admission.** The host's connector judges every export against the need's egress class. Its
//! first answer settles the run: refused, the sink logs `…; disabling OTLP trace export` and sends
//! no later batch; carried, it logs `OTLP tracing enabled`.
//!
//! **Settings** ([`OtlpSettings`]): `url`, required.
//!
//! One door, both ways in: [`door::door`] is the row a busbar build links, and the sibling
//! `busbar-export-otlp-plugin` cdylib exports the same door as its one symbol.

#![forbid(unsafe_code)]

pub mod config;
pub mod door;
pub mod proto;

pub use config::OtlpSettings;

/// THE LIMITS CHECK across every configured instance of this sink, in configuration order: the sink
/// states the `one_instance` mark, so a second instance is refused in busbar 1.5.5's words, once per
/// extra instance, naming the first.
pub fn check_limits(instances: &[String]) -> Vec<String> {
    let Some((first, rest)) = instances.split_first() else {
        return Vec::new();
    };
    rest.iter()
        .map(|name| {
            format!(
                "export.{name}: a second `module: {ALIAS}` instance (already defined as '{first}'). \
                 OTLP installs the ONE process-global tracer subscriber, so a second instance could \
                 only be silently ignored — keep a single instance."
            )
        })
        .collect()
}

/// The plugin's canonical name.
pub const NAME: &str = "busbar-stub-export-trace";
/// The module name an `export:` instance names it by.
pub const ALIAS: &str = "otlp";
/// The manifest `declares` section the signed tarball carries (`--declares-file`).
pub const DECLARES: &str = include_str!("../declares.json");

/// OTLP/HTTP's binary protobuf encoding.
pub const CONTENT_TYPE: &str = "application/x-protobuf";
/// Each export's end-to-end deadline: the ten seconds 1.5.x's exporter held its HTTP client to.
pub const EXPORT_TIMEOUT_MS: u64 = 10_000;
/// The HTTP Basic auth scheme prefix (RFC 7617), with its trailing space.
const BASIC: &str = "Basic ";

/// `url` with any userinfo (`scheme://user:pass@host/…`) replaced by `***`, safe for a log line;
/// a URL with none, or a string that is not a URL, unchanged.
pub fn mask_userinfo(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return url.to_string();
    };
    if parsed.username().is_empty() && parsed.password().is_none() {
        return url.to_string();
    }
    if parsed.set_password(None).is_err() || parsed.set_username("***").is_err() {
        let host = parsed.host_str().unwrap_or("");
        return match parsed.port() {
            Some(p) => format!("{}://***@{host}:{p}", parsed.scheme()),
            None => format!("{}://***@{host}", parsed.scheme()),
        };
    }
    parsed.into()
}

/// Split any userinfo OUT of `endpoint`: `(the endpoint without it, Some(Authorization: Basic
/// base64(user:pass)))` — RFC 7617, the userinfo percent-decoded — or `(endpoint, None)` when it
/// carries none or is not a URL. What the request carries never holds the secret in its target.
pub fn split_credentials(endpoint: &str) -> (String, Option<String>) {
    let Ok(mut parsed) = url::Url::parse(endpoint) else {
        return (endpoint.to_string(), None);
    };
    let username = parsed.username().to_string();
    let password = parsed.password().map(str::to_string);
    if username.is_empty() && password.is_none() {
        return (endpoint.to_string(), None);
    }
    let user = percent_decode(&username);
    let pass = percent_decode(password.as_deref().unwrap_or(""));
    let token = base64(format!("{user}:{pass}").as_bytes());
    let clean = if parsed.set_username("").is_err() || parsed.set_password(None).is_err() {
        let host = parsed.host_str().unwrap_or("");
        match parsed.port() {
            Some(p) => format!("{}://{host}:{p}", parsed.scheme()),
            None => format!("{}://{host}", parsed.scheme()),
        }
    } else {
        parsed.into()
    };
    (clean, Some(format!("{BASIC}{token}")))
}

/// The request target `endpoint` names: its path and query (`/` when it has no path), or `/` when
/// it is not a URL.
pub fn request_target(endpoint: &str) -> String {
    match url::Url::parse(endpoint) {
        Ok(u) => {
            let target = &u[url::Position::BeforePath..url::Position::AfterQuery];
            if target.is_empty() { "/" } else { target }.to_string()
        }
        Err(_) => "/".to_string(),
    }
}

/// Percent-decode a URL userinfo component (`%XX` → the byte; anything else as written).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex_pair = bytes
            .get(i + 1..i + 3)
            .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
            .and_then(|h| std::str::from_utf8(h).ok());
        match (
            bytes[i],
            hex_pair.and_then(|h| u8::from_str_radix(h, 16).ok()),
        ) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Standard base64 (RFC 4648 §4, `=`-padded).
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> shift) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}
