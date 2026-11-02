// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

/// One stored cookie: the three attributes that decide whether it is sent, and the value.
#[derive(Clone, Debug)]
struct Cookie {
    name: String,
    value: String,
    path: String,
    secure: bool,
}

/// A cookie store that applies RFC 6265 §5.1.4 and refuses to guess.
///
/// Deliberately hand-written and deliberately small. A general-purpose jar would be a dependency,
/// and — more to the point — this file's whole claim is that the cookie reaches the paths that read
/// it, so the code deciding that has to be visible in the test rather than three crates away.
#[derive(Default)]
pub(crate) struct Jar {
    cookies: Vec<Cookie>,
    /// `true` when the connection this jar is used over is a secure one. `Secure` cookies are
    /// stored only when it is (RFC 6265bis §5.5), which is what makes a `Secure` attribute on a
    /// plain-HTTP deployment show up here as a missing cookie rather than as nothing at all.
    secure_connection: bool,
}

impl Jar {
    pub(crate) fn new(secure_connection: bool) -> Self {
        Self {
            cookies: Vec::new(),
            secure_connection,
        }
    }

    pub(crate) fn store(&mut self, set_cookie: &str, request_path: &str) {
        let mut parts = set_cookie.split(';');
        let (name, value) = parts
            .next()
            .and_then(|nv| nv.split_once('='))
            .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
            .expect("a Set-Cookie header has a name=value pair");
        let mut path: Option<String> = None;
        let mut secure = false;
        let mut max_age: Option<i64> = None;
        for attr in parts {
            let (k, v) = match attr.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => (attr.trim(), ""),
            };
            match k.to_ascii_lowercase().as_str() {
                "path" => path = Some(v.to_string()),
                "secure" => secure = true,
                "max-age" => max_age = v.parse().ok(),
                _ => {}
            }
        }

        let path = match path {
            Some(p) if p.starts_with('/') => p,
            _ => default_path(request_path),
        };
        self.cookies.retain(|c| !(c.name == name && c.path == path));
        if max_age == Some(0) {
            return;
        }
        if secure && !self.secure_connection {
            return;
        }
        self.cookies.push(Cookie {
            name,
            value,
            path,
            secure,
        });
    }

    pub(crate) fn header_for(&self, request_path: &str) -> Option<String> {
        let sent: Vec<String> = self
            .cookies
            .iter()
            .filter(|c| path_matches(request_path, &c.path))
            .filter(|c| self.secure_connection || !c.secure)
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        (!sent.is_empty()).then(|| sent.join("; "))
    }
}

fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => request_path[..i].to_string(),
    }
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path[cookie_path.len()..].starts_with('/')
}

pub(crate) async fn send(
    client: &reqwest::Client,
    jar: &mut Jar,
    method: reqwest::Method,
    url: &str,
    form: Option<&[(&str, &str)]>,
) -> (reqwest::StatusCode, reqwest::header::HeaderMap, String) {
    let path = path_of(url);
    let mut req = client.request(method, url);
    if let Some(cookie) = jar.header_for(&path) {
        req = req.header(reqwest::header::COOKIE, cookie);
    }
    if let Some(form) = form {
        req = req.form(form);
    }
    let resp = req.send().await.expect("request");
    let status = resp.status();
    let headers = resp.headers().clone();
    for value in headers.get_all(reqwest::header::SET_COOKIE) {
        jar.store(value.to_str().expect("ASCII Set-Cookie"), &path);
    }
    let body = resp.text().await.expect("body");
    (status, headers, body)
}

pub(crate) fn path_of(url: &str) -> String {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"));
    let with_query = match rest {
        Some(rest) => match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        },
        None => url,
    };
    with_query
        .split_once('?')
        .map_or(with_query, |(p, _)| p)
        .to_string()
}

pub(crate) fn query_param(url: &str, name: &str) -> Option<String> {
    url.split(['?', '&'])
        .skip(1)
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

pub(crate) fn location(headers: &reqwest::header::HeaderMap, origin: &str) -> String {
    let raw = headers
        .get(reqwest::header::LOCATION)
        .expect("a redirect carries Location")
        .to_str()
        .expect("ASCII Location")
        .to_string();
    if raw.starts_with('/') {
        format!("{origin}{raw}")
    } else {
        raw
    }
}

pub(crate) fn encode_component(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(b).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(b) => {
                    out.push(b);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).expect("the server produced UTF-8")
}

const OFFSITE_CLIENT_ID: &str = "offsite-callback-client";
const OFFSITE_REDIRECT_URI: &str = "https://client.example/cb";
