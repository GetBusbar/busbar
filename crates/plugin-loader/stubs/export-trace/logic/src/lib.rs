// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]

pub mod config;
pub mod door;
pub mod proto;

pub use config::OtlpSettings;

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

pub const NAME: &str = "busbar-stub-export-trace";

pub const ALIAS: &str = "otlp";

pub const DECLARES: &str = include_str!("../declares.json");

pub const CONTENT_TYPE: &str = "application/x-protobuf";

pub const EXPORT_TIMEOUT_MS: u64 = 10_000;

const BASIC: &str = "Basic ";

pub fn mask_userinfo(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        if let Some((scheme, rest)) = url.split_once("://") {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            if let Some(at) = rest[..end].rfind('@') {
                return format!("{scheme}://***{}", &rest[at..]);
            }
        }
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

pub fn request_target(endpoint: &str) -> String {
    match url::Url::parse(endpoint) {
        Ok(u) => {
            let target = &u[url::Position::BeforePath..url::Position::AfterQuery];
            if target.is_empty() { "/" } else { target }.to_string()
        }
        Err(_) => "/".to_string(),
    }
}

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
