// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHO IS THE RESOURCE OWNER WHEN THERE IS NO IDENTITY PROVIDER?
//!
//! This plane exists for the deployment that has no IdP. That is also the question it has to answer
//! before it can issue anything: OAuth's authorization-code grant is a delegation, and a delegation
//! needs somebody to be delegating. With no IdP there is exactly one party this deployment can
//! authenticate — **the operator**, with the admin credential they already hold — so the operator is
//! the resource owner, and the consent screen is where they say so.
//!
//! That is a deliberate limit and it is worth stating in full: on this plane an approved client acts
//! for the OPERATOR, not for an end user, because there is no end user this deployment has any way
//! to know. A deployment that wants per-user delegation configures an IdP and uses busbar as a
//! resource server, which is the mode that already shipped.
//!
//! ## Why the operator is authenticated by the EXISTING admin chain and not by anything here
//!
//! The consent route is an ordinary busbar core route mounted `RouteAuth::Admin`, so the credential
//! is checked by `auth::run_admin_chain` — the same code, the same providers, the same
//! constant-time compare, the same scope ceiling — before the handler runs. Nothing in this file
//! verifies a credential, and that is the point: an authorization server that grew its own idea of
//! who an operator is would be a second opinion about the most privileged identity in the process.
//!
//! ## The session, and why it is one-shot at the approval rather than at the login
//!
//! Two different things are remembered, with different lifetimes and for different reasons:
//!
//! * A **session** says "this browser is the operator", and lasts minutes. It is what
//!   [`subject_resolver`] reads.
//! * An **approval** says "the operator has just agreed to THIS client for THESE scopes", and is
//!   SPENT the first time it is read. Without the spend, one approval would authorise every
//!   subsequent authorization request the same browser made — including one an attacker had
//!   arranged to be in flight.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// The `http` 1.x vocabulary types, through axum's re-export rather than as a direct dependency:
// they are the same crate and the same types, and taking them from axum means the version this
// module speaks cannot drift from the one the router speaks.
use axum::http;
// APPROVAL, not CONSENT, since 0.9.1: the library now reserves "consent" for a PERSISTED grant
// (`oauth_as::consent::ConsentRecord`, which survives the request and can be withdrawn) and calls
// the per-request prompt an APPROVAL. busbar's plane has only the prompt — it stores no
// `ConsentRecord` at all, see [`approval_resolver`] — so the types below are the whole of what it
// speaks. This module keeps the name `consent` because that is what the SCREEN is called, in the
// URL an operator sees and in the route table.
use oauth_as::http::{ApprovalDecision, ApprovalRequest};

/// The cookie the consent screen sets and [`subject_resolver`] reads. Scoped to the consent path, so it is
/// not sent to the token endpoint or to any other plane.
pub(crate) const SESSION_COOKIE: &str = "busbar_as_session";

/// How long an operator stays logged in to the consent screen. Short: this is not a product session,
/// it is the window in which one agent finishes one login.
const SESSION_TTL: Duration = Duration::from_secs(600);

/// A bound on live sessions, so an unauthenticated flood cannot grow this map. Reaching it evicts
/// the oldest, which is the correct failure: an operator whose session was evicted logs in again.
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
    /// session id -> the approvals staked for it, each `client_id\u{1f}scope`
    staked: HashMap<String, Vec<String>>,
}

/// The subject a session with no operator behind it reports.
///
/// A SENTINEL rather than `None`, because `None` makes `oauth-as` answer `403 access_denied` with no
/// way onward — which is correct for a server whose users log in elsewhere and useless for one whose
/// login screen is three lines below. Returning the sentinel lets [`decide`] answer the same request
/// with a redirect to the login screen, which is the RFC 6749 §10.12 shape: the authorization
/// endpoint is a browser endpoint and is allowed to respond with a page.
pub(crate) const PENDING: &str = "\u{0}pending";

impl Sessions {
    /// Record that this browser is the operator, and return the session id to set as a cookie.
    pub(crate) fn open(&self, subject: &str, id: String) -> String {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        inner.live.retain(|_, (_, exp)| *exp > now);
        if inner.live.len() >= MAX_SESSIONS {
            if let Some(oldest) = inner
                .live
                .iter()
                .min_by_key(|(_, (_, exp))| *exp)
                .map(|(k, _)| k.clone())
            {
                inner.live.remove(&oldest);
                inner.staked.remove(&oldest);
            }
        }
        inner
            .live
            .insert(id.clone(), (subject.to_string(), now + SESSION_TTL));
        id
    }

    /// The operator behind this session, if it is still live.
    fn subject(&self, id: &str) -> Option<String> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .live
            .get(id)
            .filter(|(_, exp)| *exp > Instant::now())
            .map(|(s, _)| s.clone())
    }

    /// Stake ONE approval for `key` against this session.
    pub(crate) fn stake(&self, id: &str, key: String) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.live.contains_key(id) {
            inner.staked.entry(id.to_string()).or_default().push(key);
        }
    }

    /// SPEND an approval. `true` at most once per [`Sessions::stake`], which is the whole reason
    /// this is not a `contains`.
    fn spend(&self, id: &str, key: &str) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let Some(pending) = inner.staked.get_mut(id) else {
            return false;
        };
        match pending.iter().position(|k| k == key) {
            Some(i) => {
                pending.swap_remove(i);
                true
            }
            None => false,
        }
    }
}

/// What an approval is FOR: one client, one exact scope set. Two different scope sets are two
/// different approvals, so an approval for `read` cannot be spent on a request for `read write`.
fn approval_key(client_id: &str, scope: &oauth_as::scope::ScopeSet) -> String {
    // The scope tokens in their own order, joined with a space, which is what the consent
    // ROUTE reconstructs from the pending request's query string. `ScopeSet` has no `as_str`,
    // and re-serialising it here rather than sorting means the two sides only agree if the
    // request that was shown is the request that is being approved.
    format!(
        "{client_id}\u{1f}{}",
        scope
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    )
}

/// The session id carried by a request, read out of the cookie header.
///
/// Hand-parsed rather than through a cookie crate: this reads ONE cookie by exact name out of a
/// header whose grammar is `name=value; name=value`, and a general-purpose parser would be a
/// dependency and an attack surface for a `split(';')`.
pub(crate) fn session_id(headers: &http::HeaderMap) -> Option<String> {
    let raw = headers.get(http::header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|pair| pair.split_once('='))
        .find(|(name, _)| name.trim() == SESSION_COOKIE)
        .map(|(_, value)| value.trim().to_string())
}

/// The subject resolver `oauth-as` calls at the authorization endpoint.
///
/// Returns [`PENDING`] rather than `None` for an unauthenticated browser; see the constant.
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

/// The approval resolver `oauth-as` calls once the request has been validated.
///
/// Three outcomes, in this order, and the order is the design: an unauthenticated browser is sent to
/// log in BEFORE it is shown what it would be approving, because a consent screen that renders for
/// an anonymous visitor is a phishing page this deployment hosts.
///
/// NOTHING IS EVER REMEMBERED HERE. The two outcomes are `Approve` — for a staked, and now spent,
/// approval — and the redirect that sends the operator to the screen; `ApproveAndRemember` is never
/// returned, so no `oauth_as::consent::ConsentRecord` is ever written and `request.remembered` is
/// always `None`. That is what makes the one-shot spend above the ONLY thing standing between an
/// authorization request and a code, which is the property this plane wants: every request is
/// shown, every request is approved on its own, and there is no stored grant that a later request
/// could be silently matched against.
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
        if sessions.spend(
            &id,
            &approval_key(request.client_id.as_str(), request.scope),
        ) {
            return ApprovalDecision::Approve;
        }
        // Logged in, nothing staked: this is the first time the operator has seen this request, so
        // send them to the screen that describes it. `Deny` here would refuse a legitimate first
        // attempt; `Approve` here would be the auto-approving conformance fixture `oauth-as`'s own
        // example warns in the loudest available terms never to copy.
        redirect(&login_url, request)
    }
}

/// A 302 to busbar's consent screen, carrying the authorization request verbatim so the screen can
/// hand the browser back to `/authorize` unchanged once the operator has decided.
///
/// The `return` parameter is the request URI this server itself received and already validated, not
/// a URL a caller supplied, so echoing it is not an open redirect: it is percent-encoded into a
/// query parameter of our own origin and is only ever used to rebuild a path on this host.
fn redirect(login_url: &str, request: &ApprovalRequest<'_>) -> ApprovalDecision {
    let target = format!(
        "{login_url}?return={}",
        percent_encode(&request.uri.to_string())
    );
    let response = http::Response::builder()
        .status(http::StatusCode::FOUND)
        .header(http::header::LOCATION, target)
        // A consent redirect is a per-request decision and must never be cached: a cached 302 would
        // send a later, different authorization request to a screen describing an earlier one.
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(oauth_as::http::Body::empty());
    match response {
        Ok(r) => ApprovalDecision::Respond(Box::new(r)),
        // Unreachable: every header value above is built from an already-validated URI. A refusal
        // rather than an unwrap, because this is a request path.
        Err(_) => ApprovalDecision::Deny,
    }
}

/// Percent-encode everything outside the RFC 3986 unreserved set.
///
/// Deliberately over-encoding rather than reproducing a reserved-character table: this value goes
/// into a query parameter and is decoded whole, so encoding more than strictly necessary is correct
/// and encoding less is a parameter-splitting bug.
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
