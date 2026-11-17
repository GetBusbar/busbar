// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::response::{IntoResponse, Response};

pub(super) fn as_plane(app: &busbar_kernel::state::App) -> Option<&super::plane::AsPlane> {
    app.oauth_as_any()
        .and_then(|p| p.downcast_ref::<super::plane::AsPlane>())
}

pub(crate) async fn forward(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    request: axum::extract::Request,
) -> Response {
    let Some(plane) = as_plane(&app) else {
        return not_found();
    };
    into_axum(plane.handle(request).await)
}

fn into_axum(response: oauth_as::http::Response) -> Response {
    response
        .map(|body| axum::body::Body::from(body.into_bytes()))
        .into_response()
}

/// `GET {issuer}/authorize` — [`forward`], with the two things a BROWSER endpoint owes a browser.
///
/// 1. **A pushed request is decided before `oauth-as` sees it.** Under RFC 9126 the URL carries only
///    `client_id` and `request_uri`, and `oauth-as` spends the handle on arrival. Sent to the
///    library undecided, the request would be spent by merely loading the page, and the operator's
///    answer would come back to a handle that no longer exists. So an undecided pushed request goes
///    straight to the consent screen, and reaches the library only once an approval or a refusal is staked for
///    it — one-time use enforced at the point of authorization (FAPI 2.0 s5.3.2.2 NOTE 3). A
///    `request_uri` this store does not hold, or one presented by a client that did not push it,
///    goes to the library, which refuses it.
/// 2. **A refusal is a page.** `oauth-as` answers a request it will not redirect (RFC 6749
///    s4.1.2.1: never to an unvalidated `redirect_uri`) with a direct JSON error, which a browser
///    shows as raw text. The same status and the same error code go back as HTML instead.
pub(crate) async fn authorize(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    request: axum::extract::Request,
) -> Response {
    let Some(plane) = as_plane(&app) else {
        return not_found();
    };
    // 3. **The starting browser is named by its start cookie S** (#140), minted here only if it has
    //    none, and never stored: an unauthenticated endpoint must not fill the session table.
    let (start, minted) = match super::consent::start_of(request.headers()) {
        Some(start) => (start, false),
        None => match super::consent::new_handle() {
            Some(start) => (start, true),
            None => return no_entropy(),
        },
    };
    // 4. **The one-time T the consent page appended is removed VERBATIM** before the library sees
    //    the request: the stake's key is computed from the request's exact bytes.
    let (request, handle) = match without_handle(request) {
        Ok(split) => split,
        Err(refused) => return refused,
    };
    let browser = super::consent::Browser {
        session: super::consent::session_of(&start),
        handle,
    };
    let undecided = match GateInputs::of(&request) {
        Some(gate) => pushed_request_gate(plane, gate, &browser).await,
        None => None,
    };
    let mut response = match undecided {
        Some(undecided) => into_axum(undecided),
        None => error_page(plane.authorize(request, browser).await),
    };
    if minted {
        let cookie = super::consent::start_cookie(plane.identity(), &start);
        let Ok(cookie) = axum::http::HeaderValue::from_str(&cookie) else {
            return not_representable();
        };
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, cookie);
    }
    response
}

/// The request without its trailing `busbar_consent=<T>`, and T.
fn without_handle(
    request: axum::extract::Request,
) -> Result<(axum::extract::Request, Option<String>), Response> {
    let split = request
        .uri()
        .path_and_query()
        .and_then(|pq| super::consent::split_handle(pq.as_str()))
        .map(|(base, handle)| (base.parse::<axum::http::Uri>(), handle.to_string()));
    let Some((uri, handle)) = split else {
        return Ok((request, None));
    };
    let Ok(uri) = uri else {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            crate::page::Page(PAGE_NO_REQUEST),
        )
            .into_response());
    };
    let (mut parts, body) = request.into_parts();
    parts.uri = uri;
    Ok((
        axum::extract::Request::from_parts(parts, body),
        Some(handle),
    ))
}

struct GateInputs {
    client_id: String,
    request_uri: String,
    target: String,
}

impl GateInputs {
    fn of(request: &axum::extract::Request) -> Option<Self> {
        let pairs = form_urlencoded_pairs(request.uri().query()?);
        let param = |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        Some(Self {
            client_id: param("client_id")?,
            request_uri: param("request_uri")?,
            target: request.uri().path_and_query()?.as_str().to_string(),
        })
    }
}

/// A pushed request reaches the library only once an answer is staked for it under THIS browser's
/// consent session WITH the T it came back with: a wrong or missing T never reaches the library,
/// so it cannot burn the one-time `request_uri`.
async fn pushed_request_gate(
    plane: &super::plane::AsPlane,
    gate: GateInputs,
    browser: &super::consent::Browser,
) -> Option<oauth_as::http::Response> {
    let pushed = plane.pushed(&gate.request_uri).await?;
    if pushed.client_id != gate.client_id {
        return None;
    }
    let key = super::consent::pushed_key(&gate.client_id, &gate.request_uri);
    let decided = match &browser.handle {
        Some(handle) => {
            plane
                .is_staked(&browser.session, &super::consent::handled_key(&key, handle))
                .await
        }
        None => false,
    };
    if decided {
        return None;
    }
    Some(super::consent::login_redirect(
        &plane.consent_url(),
        &gate.target,
        &browser.session,
    ))
}

fn error_page(response: oauth_as::http::Response) -> Response {
    let json = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !response.status().is_client_error() || !json {
        return into_axum(response);
    }
    let (parts, body) = response.into_parts();
    let page = super::cold::authorization_error_page(parts.status, &body.into_bytes());
    (
        parts.status,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        crate::page::Page(page),
    )
        .into_response()
}

pub(super) fn unresolved_grant(error: &oauth_as::store::StorageError) -> Response {
    tracing::warn!(%error, "oauth_as: the consent grant could not be resolved");
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        crate::page::Page(PAGE_UNRESOLVED_GRANT),
    )
        .into_response()
}

pub(super) fn query_value(target: &str, name: &str) -> Option<String> {
    form_urlencoded_pairs(target.split_once('?')?.1)
        .into_iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v)
}

pub(super) struct Pending {
    pub(super) client_id: String,

    pub(super) scope: String,
    pub(super) redirect_host: String,

    pub(super) revisit: bool,
}

pub(super) async fn pending_request(
    plane: &super::plane::AsPlane,
    target: &str,
) -> Result<Pending, oauth_as::store::StorageError> {
    let (client_id, scope, redirect_host) = client_and_scope_of(target)
        .unwrap_or_else(|| ("(unnamed)".to_string(), None, String::new()));
    let mut pushed = None;
    if let Some(handle) = query_value(target, "request_uri") {
        if let Some(p) = plane
            .pushed(&handle)
            .await
            .filter(|p| p.client_id == client_id)
        {
            let revisit = plane.mark_pushed_shown(&handle).await;
            pushed = Some((p, revisit));
        }
    }
    let (requested, redirect_host, revisit) = match pushed {
        Some((p, revisit)) => (p.scope, host_of(&p.redirect_uri), revisit),
        None => (scope, redirect_host, false),
    };
    Ok(Pending {
        scope: plane
            .granted_scope(&client_id, requested.as_deref())
            .await?,
        client_id,
        redirect_host,
        revisit,
    })
}

pub(super) fn is_local_path(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next() == Some(b'/')
        && !matches!(bytes.next(), Some(b'/' | b'\\'))
        && !value
            .chars()
            .any(|c| c == '\\' || c.is_control() || c.is_whitespace())
}

pub(super) fn client_and_scope_of(target: &str) -> Option<(String, Option<String>, String)> {
    let query = target.split_once('?')?.1;
    let mut client_id = None;
    let mut scope = None;
    let mut redirect_uri = None;
    for (name, value) in form_urlencoded_pairs(query) {
        let slot = match name.as_str() {
            "client_id" => &mut client_id,
            "scope" => &mut scope,
            "redirect_uri" => &mut redirect_uri,
            _ => continue,
        };
        if slot.is_none() {
            *slot = Some(value);
        }
    }
    Some((
        client_id?,
        scope,
        host_of(redirect_uri.as_deref().unwrap_or_default()),
    ))
}

fn host_of(redirect_uri: &str) -> String {
    let Ok(parts) = busbar_contract::net::parse_url(redirect_uri) else {
        return String::new();
    };

    if busbar_contract::net::target_host(redirect_uri).is_none() {
        return String::new();
    }
    let host = if parts.host.contains(':') {
        format!("[{}]", parts.host)
    } else {
        parts.host
    };
    match parts.port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

pub(super) fn form_urlencoded_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (form_decoded(k), form_decoded(v)))
        .collect()
}

/// One form component: `+` is a space and every `%XX` escape is decoded by percent-encoding (a `%`
/// short of two hex digits stays); invalid UTF-8 is replaced. `+` is not a hex digit, so no escape
/// spans a `+`.
fn form_decoded(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    for (i, piece) in s.split('+').enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        out.extend(percent_encoding::percent_decode_str(piece));
    }
    match String::from_utf8(out) {
        Ok(text) => text,
        Err(invalid) => super::cold::lossy_form_component(invalid.as_bytes()),
    }
}

pub(super) fn no_entropy() -> Response {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        crate::page::Page(PAGE_NO_SESSION),
    )
        .into_response()
}

pub(super) fn not_representable() -> Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        crate::page::Page(PAGE_NO_SESSION),
    )
        .into_response()
}

pub(super) fn not_found() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        r#"{"error":"not_found"}"#,
    )
        .into_response()
}

pub(super) const PAGE_NO_REQUEST: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>There is no authorization request waiting. Start the login from your agent.</p>";

pub(super) const PAGE_NO_SESSION: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>This server could not start a session. Try again, and tell your operator if it persists.</p>";

const PAGE_UNRESOLVED_GRANT: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>This server could not resolve the requested permissions. Try again, and tell your operator \
    if it persists.</p>";

/// Text made safe for HTML as it is written into the page.
pub(super) struct Escaped<'a>(pub(super) &'a str);

impl std::fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut rest = self.0;
        while let Some(at) = rest.find(['&', '<', '>', '"', '\'']) {
            f.write_str(&rest[..at])?;
            f.write_str(match rest.as_bytes()[at] {
                b'&' => "&amp;",
                b'<' => "&lt;",
                b'>' => "&gt;",
                b'"' => "&quot;",
                _ => "&#39;",
            })?;
            rest = &rest[at + 1..];
        }
        f.write_str(rest)
    }
}

#[cfg(test)]
#[path = "tests/percent_decode_tests.rs"]
mod percent_decode_tests;

#[cfg(test)]
#[path = "tests/consent_host_tests.rs"]
mod consent_host_tests;

#[cfg(test)]
#[path = "tests/local_path_tests.rs"]
mod local_path_tests;

#[cfg(test)]
#[path = "tests/consent_resolution_tests.rs"]
mod consent_resolution_tests;

#[cfg(test)]
#[path = "tests/form_codec_tests.rs"]
mod form_codec_tests;
