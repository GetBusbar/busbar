// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http;

use oauth_as::http::{ApprovalDecision, ApprovalRequest};

pub(crate) const SESSION_COOKIE: &str = "busbar_as_session";

pub(crate) const SESSION_TTL: Duration = Duration::from_secs(600);

const MAX_SESSIONS: usize = 64;

/// The sessions and the staked approvals, shared by the two closures the service is built with.
///
/// Held behind one `Mutex` rather than two: every operation touches at most one map, the critical
/// sections are microseconds, and two locks in a consent path is an ordering rule somebody has to
/// remember.
#[derive(Default)]
pub(crate) struct Sessions {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// session id -> (subject, when it expires)
    live: HashMap<String, (String, Instant)>,
    /// session id -> the answers staked for it: each key ([`request_key`], or [`pushed_key`] for a
    /// pushed request) with `true` for an approval and `false` for a refusal.
    staked: HashMap<String, Vec<(String, bool)>>,
}

pub(crate) const PENDING: &str = "\u{0}pending";

impl Inner {
    fn make_room(&mut self, now: Instant) {
        let Inner { live, staked } = self;
        live.retain(|_, (_, exp)| *exp > now);
        if live.len() >= MAX_SESSIONS {
            if let Some(oldest) = live
                .iter()
                .min_by_key(|(_, (_, exp))| *exp)
                .map(|(k, _)| k.clone())
            {
                live.remove(&oldest);
            }
        }
        staked.retain(|id, _| live.contains_key(id));
    }
}

impl Sessions {
    pub(crate) fn open(&self, subject: &str, id: String) -> String {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        inner.make_room(now);
        inner
            .live
            .insert(id.clone(), (subject.to_string(), now + SESSION_TTL));
        id
    }

    pub(crate) fn hydrate(&self, id: &str, subject: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.live.contains_key(id) {
            return;
        }
        let now = Instant::now();
        inner.make_room(now);
        inner
            .live
            .insert(id.to_string(), (subject.to_string(), now + SESSION_TTL));
    }

    pub(crate) fn plant(&self, id: &str, key: String, approve: bool) {
        self.stake(id, key, approve);
    }

    pub(crate) fn subject(&self, id: &str) -> Option<String> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .live
            .get(id)
            .filter(|(_, exp)| *exp > Instant::now())
            .map(|(s, _)| s.clone())
    }

    pub(crate) fn stake(&self, id: &str, key: String, approve: bool) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.live.contains_key(id) {
            let pending = inner.staked.entry(id.to_string()).or_default();
            match pending.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = approve,
                None => pending.push((key, approve)),
            }
        }
    }

    pub(crate) fn is_staked(&self, id: &str, key: &str) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .staked
            .get(id)
            .is_some_and(|pending| pending.iter().any(|(k, _)| k == key))
    }

    pub(crate) fn spend(&self, id: &str, key: &str) -> Option<bool> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let pending = inner.staked.get_mut(id)?;
        let i = pending.iter().position(|(k, _)| k == key)?;
        Some(pending.swap_remove(i).1)
    }
}

pub(crate) fn request_key(client_id: &str, target: &str) -> String {
    format!("{client_id}\u{1f}\u{1d}{target}")
}

pub(crate) fn pushed_key(client_id: &str, request_uri: &str) -> String {
    format!("{client_id}\u{1f}\u{1e}{request_uri}")
}

fn staked_key(request: &ApprovalRequest<'_>) -> String {
    let request_uri = request.uri.query().and_then(|q| {
        super::routes::form_urlencoded_pairs(q)
            .into_iter()
            .find(|(k, _)| k == "request_uri")
            .map(|(_, v)| v)
    });
    match request_uri {
        Some(handle) => pushed_key(request.client_id.as_str(), &handle),
        None => request_key(
            request.client_id.as_str(),
            request.uri.path_and_query().map_or("", |p| p.as_str()),
        ),
    }
}

pub(crate) fn session_id(headers: &http::HeaderMap) -> Option<String> {
    for raw in headers.get_all(http::header::COOKIE) {
        let raw = raw.to_str().ok()?;
        if let Some((_, value)) = raw
            .split(';')
            .filter_map(|pair| pair.split_once('='))
            .find(|(name, _)| name.trim() == SESSION_COOKIE)
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

pub(crate) fn subject_resolver(
    sessions: Arc<Sessions>,
) -> impl Fn(&http::HeaderMap) -> Option<String> + Send + Sync + 'static {
    move |headers| {
        Some(
            session_id(headers)
                .and_then(|id| sessions.subject(&id))
                .unwrap_or_else(|| PENDING.to_string()),
        )
    }
}

pub(crate) fn approval_resolver(
    sessions: Arc<Sessions>,
    login_url: String,
) -> impl Fn(&ApprovalRequest<'_>) -> ApprovalDecision + Send + Sync + 'static {
    move |request| {
        let Some(id) = session_id(request.headers) else {
            return redirect(&login_url, request);
        };
        if request.subject == PENDING || sessions.subject(&id).is_none() {
            return redirect(&login_url, request);
        }
        match sessions.spend(&id, &staked_key(request)) {
            Some(true) => return ApprovalDecision::Approve,

            Some(false) => return ApprovalDecision::Deny,
            None => {}
        }

        redirect(&login_url, request)
    }
}

fn redirect(login_url: &str, request: &ApprovalRequest<'_>) -> ApprovalDecision {
    ApprovalDecision::Respond(Box::new(login_redirect(
        login_url,
        &request.uri.to_string(),
    )))
}

pub(crate) fn login_redirect(login_url: &str, target: &str) -> oauth_as::http::Response {
    let target = format!("{login_url}?return={}", percent_encode(target));
    let response = http::Response::builder()
        .status(http::StatusCode::FOUND)
        .header(http::header::LOCATION, target)
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(oauth_as::http::Body::empty());
    match response {
        Ok(r) => r,

        Err(e) => {
            tracing::warn!(
                error = %e,
                "oauth_as: the login redirect URL could not be encoded into a Location header; \
                 failing closed with a 502 rather than answering access_denied on the operator's \
                 behalf"
            );
            unencodable_login_redirect()
        }
    }
}

fn unencodable_login_redirect() -> oauth_as::http::Response {
    http::Response::builder()
        .status(http::StatusCode::BAD_GATEWAY)
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(oauth_as::http::Body::from(
            "This deployment's login redirect is misconfigured and could not be sent. Tell your \
             operator.",
        ))
        .expect("a response built entirely from `'static` bytes must be representable")
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/consent_tests.rs"]
mod consent_tests;
