// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The consent hop between the authorization endpoint (data listener, issuer origin) and the
//! consent page (admin listener, admin origin), and the library hooks that read its outcome (#140).
//!
//! 1. `/authorize`, undecided: the browser's start cookie S (minted only if absent, never stored)
//!    names it; the browser goes to `{admin}/oauth/consent?return=<target>&ref=<hex SHA-256(S)>`.
//! 2. The operator answers there; the answer is staked under `ref` together with a one-time T, and
//!    the browser comes back to `{issuer}{target}` with `busbar_consent=T` appended.
//! 3. `/authorize` strips that parameter VERBATIM before the library sees the request, and spends the
//!    stake only for session `SHA-256(S)` with a matching T. Spending needs S (only in the starting
//!    browser) and T (only delivered to the approving browser), and both are single use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http;

use oauth_as::http::{ApprovalDecision, ApprovalRequest};

/// The start cookie S: set by `/authorize` on the issuer origin, scoped to the authorization path,
/// so it never reaches the admin listener's pages (loopback origins share host-only cookies across
/// ports, so the PATH is what keeps them apart).
pub(crate) const START_COOKIE: &str = "busbar_as_start";

/// The query parameter that carries the one-time T back to `/authorize`.
pub(crate) const HANDLE_PARAM: &str = "busbar_consent";

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
    /// session id -> the answers staked for it: each key ([`handled_key`] over [`request_key`], or
    /// over [`pushed_key`] for a pushed request) with `true` for an approval and `false` for a
    /// refusal.
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

/// A request key bound to the one-time T it was answered with: the stake is spent only by a
/// request that presents the same T.
/// `key` is extended in place (the request key is made for this and not used again): no second
/// copy of it.
pub(crate) fn handled_key(mut key: String, handle: &str) -> String {
    key.push_str("\u{1f}\u{1c}");
    key.push_str(handle);
    key
}

fn staked_key(request: &ApprovalRequest<'_>) -> String {
    let request_uri = request.uri.query().and_then(|q| {
        super::routes::form_urlencoded_pairs(q)
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

/// The first `name=` value among the request's `Cookie` fields. An unreadable field before it
/// refuses the lookup rather than skipping to a later one.
pub(crate) fn cookie(headers: &http::HeaderMap, name: &str) -> Option<String> {
    for raw in headers.get_all(http::header::COOKIE) {
        let raw = raw.to_str().ok()?;
        if let Some((_, value)) = raw
            .split(';')
            .filter_map(|pair| pair.split_once('='))
            .find(|(n, _)| n.trim() == name)
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// A value this crate minted with [`new_handle`]: 32 random bytes as 64 lowercase hex digits.
pub(crate) fn is_handle(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A handle ([`is_handle`]: 64 lowercase hex digits) held by value: no heap text to make or free.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Handle([u8; 64]);

impl Handle {
    /// `text` as a handle, when it is one.
    pub(crate) fn of(text: &str) -> Option<Self> {
        if !is_handle(text) {
            return None;
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(text.as_bytes());
        Some(Self(bytes))
    }

    /// The handle's text.
    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

/// 32 fresh random bytes as 64 lowercase hex digits; `None` when the system has no entropy.
pub(crate) fn new_handle() -> Option<String> {
    let mut bytes = [0u8; 32];
    busbar_contract::crypto::fill(&mut bytes).ok()?;
    Some(hex::encode(bytes))
}

/// The consent session a start cookie names: `hex(SHA-256(S))`. The `ref` the consent page carries,
/// and the id the operator's answer is staked under.
pub(crate) fn session_of(start: &str) -> String {
    hex::encode(busbar_contract::crypto::sha256(start.as_bytes()))
}

/// The browser's start cookie S, if it carries one this crate minted.
pub(crate) fn start_of(headers: &http::HeaderMap) -> Option<String> {
    cookie(headers, START_COOKIE).filter(|s| is_handle(s))
}

/// `Set-Cookie` for a fresh start cookie: on the issuer origin, scoped to the authorization path,
/// `SameSite=Lax` (the flow starts with a cross-site top-level navigation, and comes back with one).
pub(crate) fn start_cookie(identity: &crate::config::AsIdentity, start: &str) -> String {
    let secure = if identity.issuer().starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{START_COOKIE}={start}; Path={}; HttpOnly{secure}; SameSite=Lax; Max-Age={}",
        identity.authorize_path(),
        SESSION_TTL.as_secs(),
    )
}

/// The trailing `busbar_consent=<T>` the consent page appended to a request, split off VERBATIM:
/// `(the request exactly as it was before, T)`. Never re-serialised, because the stake's key is
/// computed from the request's bytes. `None` unless the parameter is the exact trailing one.
pub(crate) fn split_handle(path_and_query: &str) -> Option<(&str, &str)> {
    let at = path_and_query.len().checked_sub(64)?;
    if !path_and_query.is_char_boundary(at) {
        return None;
    }
    let (head, handle) = path_and_query.split_at(at);
    if !is_handle(handle) {
        return None;
    }
    let head = head.strip_suffix('=')?.strip_suffix(HANDLE_PARAM)?;
    let base = head.strip_suffix('&').or_else(|| head.strip_suffix('?'))?;
    Some((base, handle))
}

/// The starting browser, as `/authorize` resolved it: the consent session its start cookie names,
/// and the one-time T it came back with, if any. Lent to the library's synchronous hooks for the
/// one request being answered.
pub(crate) struct Browser {
    pub(crate) session: String,
    pub(crate) handle: Option<Handle>,
}

tokio::task_local! {
    static BROWSER: Browser;
}

/// Run `answer` with `browser` lent to the library's hooks.
pub(crate) async fn as_browser<F: std::future::Future>(browser: Browser, answer: F) -> F::Output {
    BROWSER.scope(browser, answer).await
}

pub(crate) fn subject_resolver(
    sessions: Arc<Sessions>,
) -> impl Fn(&http::HeaderMap) -> Option<String> + Send + Sync + 'static {
    move |_headers| {
        Some(
            BROWSER
                .try_with(|browser| sessions.subject(&browser.session))
                .ok()
                .flatten()
                .unwrap_or_else(|| PENDING.to_string()),
        )
    }
}

pub(crate) fn approval_resolver(
    sessions: Arc<Sessions>,
    login_url: String,
) -> impl Fn(&ApprovalRequest<'_>) -> ApprovalDecision + Send + Sync + 'static {
    move |request| {
        let Ok((session, handle)) =
            BROWSER.try_with(|browser| (browser.session.clone(), browser.handle))
        else {
            return ApprovalDecision::Respond(Box::new(no_browser()));
        };
        if request.subject == PENDING || sessions.subject(&session).is_none() {
            return redirect(&login_url, request, &session);
        }
        if let Some(handle) = handle {
            match sessions.spend(&session, &handled_key(staked_key(request), handle.as_str())) {
                Some(true) => return ApprovalDecision::Approve,
                Some(false) => return ApprovalDecision::Deny,
                None => {}
            }
        }
        redirect(&login_url, request, &session)
    }
}

fn redirect(login_url: &str, request: &ApprovalRequest<'_>, session: &str) -> ApprovalDecision {
    ApprovalDecision::Respond(Box::new(login_redirect(
        login_url,
        &request.uri.to_string(),
        session,
    )))
}

/// `302` to the consent page on the admin origin, naming the pending request and the starting
/// browser's consent session.
pub(crate) fn login_redirect(
    login_url: &str,
    target: &str,
    session: &str,
) -> oauth_as::http::Response {
    let target = format!(
        "{login_url}?return={}&ref={}",
        percent_encode(target),
        percent_encode(session)
    );
    let response = http::Response::builder()
        .status(http::StatusCode::FOUND)
        .header(http::header::LOCATION, target)
        .header(http::header::CACHE_CONTROL, "no-store")
        .header(http::header::REFERRER_POLICY, "no-referrer")
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

/// The authorization endpoint reached without a resolved browser: never through busbar's own
/// route, which always resolves one. Refused rather than guessed.
fn no_browser() -> oauth_as::http::Response {
    http::Response::builder()
        .status(http::StatusCode::BAD_REQUEST)
        .header(http::header::CACHE_CONTROL, "no-store")
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(oauth_as::http::Body::from(
            "<!doctype html><meta charset=utf-8><title>busbar</title>\
             <p>There is no authorization request waiting. Start the login from your agent.</p>",
        ))
        .expect("a response built entirely from `'static` bytes must be representable")
}

/// `s` percent-encoded, as written where it is formatted (no text of its own).
fn percent_encode(s: &str) -> percent_encoding::PercentEncode<'_> {
    percent_encoding::utf8_percent_encode(s, busbar_contract::net::UNRESERVED_KEPT)
}

#[cfg(test)]
#[path = "tests/consent_tests.rs"]
mod consent_tests;
