// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_kernel::core_routes::CoreRouter;

pub(crate) fn seam_mount(
    router: CoreRouter,
    plane: Option<&Arc<dyn std::any::Any + Send + Sync>>,
) -> CoreRouter {
    mount(
        router,
        plane.and_then(|p| p.downcast_ref::<super::plane::AsPlane>()),
    )
}

pub(crate) fn mount(router: CoreRouter, plane: Option<&super::plane::AsPlane>) -> CoreRouter {
    let Some(plane) = plane else {
        return router;
    };
    let id = plane.identity();

    let router = if id.fapi2() {
        router.route(
            id.par_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        )
    } else {
        router
    };
    router
        .route(
            id.metadata_path().to_string(),
            RouteMethod::Get,
            RouteAuth::None,
            forward,
        )
        .route(
            id.jwks_path().to_string(),
            RouteMethod::Get,
            RouteAuth::None,
            forward,
        )
        .route(
            id.authorize_path().to_string(),
            RouteMethod::Get,
            RouteAuth::None,
            authorize,
        )
        .route(
            id.token_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        )
        .route(
            id.device_authorization_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        )
        .route(
            id.revocation_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        )
        .route(
            id.verification_path().to_string(),
            RouteMethod::Get,
            RouteAuth::Admin,
            device_verification,
        )
        .route(
            id.verification_path().to_string(),
            RouteMethod::Post,
            RouteAuth::Admin,
            device_verification,
        )
        .route(
            id.consent_path().to_string(),
            RouteMethod::Get,
            RouteAuth::Admin,
            consent_screen,
        )
        .route(
            id.consent_path().to_string(),
            RouteMethod::Post,
            RouteAuth::Admin,
            consent_submit,
        )
        .route(
            id.register_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        )
}

fn as_plane(app: &busbar_kernel::state::App) -> Option<&super::plane::AsPlane> {
    app.oauth_as_any()
        .and_then(|p| p.downcast_ref::<super::plane::AsPlane>())
}

async fn forward(
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

async fn device_verification(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    request: axum::extract::Request,
) -> Response {
    let Some(plane) = as_plane(&app) else {
        return not_found();
    };
    let (request, consumed) = if request.method() == axum::http::Method::POST {
        let (parts, body) = request.into_parts();
        let bytes = match axum::body::to_bytes(body, oauth_as::http::MAX_BODY_BYTES).await {
            Ok(bytes) => bytes,
            Err(_) => return axum::http::StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        };
        let session = device_session_id(&parts.headers);
        let csrf = form_urlencoded_pairs(&String::from_utf8_lossy(&bytes))
            .into_iter()
            .find(|(key, _)| key == "csrf_token")
            .map(|(_, value)| value);
        let consumed = match (session, csrf) {
            (Some(session), Some(csrf)) if !csrf.is_empty() => {
                match plane
                    .consume_device_form(&session, &csrf, ADMIN_SUBJECT)
                    .await
                {
                    Ok(true) => Some(csrf),
                    Ok(false) => None,
                    Err(error) => {
                        tracing::warn!(%error, "oauth_as: the device form could not be consumed");
                        return device_store_unavailable();
                    }
                }
            }
            _ => None,
        };
        (
            axum::extract::Request::from_parts(parts, axum::body::Body::from(bytes)),
            consumed,
        )
    } else {
        (request, None)
    };

    let (Some(session), Some(csrf)) = (new_session_id(), new_session_id()) else {
        return no_entropy();
    };
    if let Err(error) = plane
        .issue_device_form(&session, &csrf, ADMIN_SUBJECT)
        .await
    {
        tracing::warn!(%error, "oauth_as: the device form could not be kept");
        return device_store_unavailable();
    }
    let cookie = device_session_cookie(plane.identity(), &session);
    let Ok(cookie) = axum::http::HeaderValue::from_str(&cookie) else {
        return not_representable();
    };
    let mut response = into_axum(
        plane
            .handle_device(request, ADMIN_SUBJECT, csrf, consumed)
            .await,
    );
    response
        .headers_mut()
        .append(axum::http::header::SET_COOKIE, cookie);
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

const DEVICE_SESSION_COOKIE: &str = "busbar_as_device";

fn device_session_id(headers: &axum::http::HeaderMap) -> Option<String> {
    for raw in headers.get_all(axum::http::header::COOKIE) {
        let raw = raw.to_str().ok()?;
        if let Some((_, value)) = raw
            .split(';')
            .filter_map(|pair| pair.split_once('='))
            .find(|(name, _)| name.trim() == DEVICE_SESSION_COOKIE)
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn device_session_cookie(identity: &crate::config::AsIdentity, id: &str) -> String {
    let secure = if identity.issuer().starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{DEVICE_SESSION_COOKIE}={id}; Path={}; HttpOnly{secure}; SameSite=Lax; Max-Age={}",
        identity.verification_path(),
        super::consent::SESSION_TTL.as_secs(),
    )
}

fn device_store_unavailable() -> Response {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        axum::response::Html(PAGE_NO_SESSION),
    )
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
async fn authorize(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    request: axum::extract::Request,
) -> Response {
    let Some(plane) = as_plane(&app) else {
        return not_found();
    };
    if let Some(gate) = GateInputs::of(&request) {
        if let Some(undecided) = pushed_request_gate(plane, gate).await {
            return into_axum(undecided);
        }
    }
    error_page(plane.handle(request).await)
}

struct GateInputs {
    client_id: String,
    request_uri: String,
    session: Option<String>,
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
            session: super::consent::session_id(request.headers()),
            target: request.uri().path_and_query()?.as_str().to_string(),
        })
    }
}

async fn pushed_request_gate(
    plane: &super::plane::AsPlane,
    gate: GateInputs,
) -> Option<oauth_as::http::Response> {
    let pushed = plane.pushed(&gate.request_uri).await?;
    if pushed.client_id != gate.client_id {
        return None;
    }
    let key = super::consent::pushed_key(&gate.client_id, &gate.request_uri);
    let decided = match &gate.session {
        Some(session) => plane.is_staked(session, &key).await,
        None => false,
    };
    if decided {
        return None;
    }
    Some(super::consent::login_redirect(
        &plane.identity().consent_url(),
        &gate.target,
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
    let error: serde_json::Value = serde_json::from_slice(&body.into_bytes()).unwrap_or_default();
    let code = error["error"]
        .as_str()
        .map_or_else(|| format!("HTTP {}", parts.status.as_u16()), str::to_string);
    let description = error["error_description"].as_str().unwrap_or_default();
    let page = format!(
        "<!doctype html><meta charset=utf-8><title>busbar — authorization error</title>\
         <h1>Authorization error</h1>\
         <p>error: <code>{code}</code></p>\
         <p>{description}</p>",
        code = escape(&code),
        description = escape(description),
    );
    (
        parts.status,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        axum::response::Html(page),
    )
        .into_response()
}

fn unresolved_grant(error: &oauth_as::store::StorageError) -> Response {
    tracing::warn!(%error, "oauth_as: the consent grant could not be resolved");
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        axum::response::Html(PAGE_UNRESOLVED_GRANT),
    )
        .into_response()
}

async fn consent_screen(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    axum::extract::Query(query): axum::extract::Query<ConsentQuery>,
) -> Response {
    let Some(plane) = as_plane(&app) else {
        return not_found();
    };
    let Some(target) = query.return_to.as_deref().filter(|t| is_local_path(t)) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::response::Html(PAGE_NO_REQUEST.to_string()),
        )
            .into_response();
    };
    let pending = match pending_request(plane, target).await {
        Ok(pending) => pending,
        Err(error) => return unresolved_grant(&error),
    };

    let Some(id) = new_session_id() else {
        return no_entropy();
    };
    plane.open_session(ADMIN_SUBJECT, id.clone()).await;
    let page = consent_page(target, &pending);

    let mut response = axum::response::Html(page).into_response();
    let headers = response.headers_mut();
    for cookie in session_cookies(plane.identity(), &id) {
        let Ok(value) = axum::http::HeaderValue::from_str(&cookie) else {
            return not_representable();
        };

        headers.append(axum::http::header::SET_COOKIE, value);
    }

    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

pub(super) fn session_cookies(identity: &crate::config::AsIdentity, id: &str) -> [String; 2] {
    let secure = if identity.issuer().starts_with("https://") {
        "; Secure"
    } else {
        ""
    };

    let attrs = format!(
        "HttpOnly{secure}; SameSite=Lax; Max-Age={}",
        super::consent::SESSION_TTL.as_secs()
    );
    let name = super::consent::SESSION_COOKIE;
    [
        format!("{name}={id}; Path={}; {attrs}", identity.authorize_path()),
        format!("{name}={id}; Path={}; {attrs}", identity.consent_path()),
    ]
}

async fn consent_submit(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    headers: axum::http::HeaderMap,
    axum::extract::Form(form): axum::extract::Form<ConsentForm>,
) -> Response {
    let Some(plane) = as_plane(&app) else {
        return not_found();
    };
    let Some(target) = form.return_to.as_deref().filter(|t| is_local_path(t)) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::response::Html(PAGE_NO_REQUEST.to_string()),
        )
            .into_response();
    };

    let Some(session) = super::consent::session_id(&headers) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::response::Html(PAGE_NO_REQUEST.to_string()),
        )
            .into_response();
    };

    let approve = match form.answer.as_deref() {
        None | Some("approve") => true,
        Some("deny") => false,
        Some(_) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::response::Html(PAGE_NO_REQUEST.to_string()),
            )
                .into_response()
        }
    };

    if let Some((client_id, _scope, _redirect_host)) = client_and_scope_of(target) {
        let key = match query_value(target, "request_uri") {
            Some(handle) => super::consent::pushed_key(&client_id, &handle),
            None => super::consent::request_key(&client_id, target),
        };
        plane.stake(&session, key, approve).await;
    }
    (
        axum::http::StatusCode::FOUND,
        [
            (axum::http::header::LOCATION, target.to_string()),
            (axum::http::header::CACHE_CONTROL, "no-store".to_string()),
        ],
    )
        .into_response()
}

const ADMIN_SUBJECT: &str = "busbar-operator";

/// `?return=` on the consent screen.
#[derive(serde::Deserialize)]
struct ConsentQuery {
    #[serde(rename = "return")]
    return_to: Option<String>,
}

/// The consent form's fields: the pending request, and which button was pressed.
#[derive(serde::Deserialize)]
struct ConsentForm {
    #[serde(rename = "return")]
    return_to: Option<String>,
    /// `approve` or `deny`.
    answer: Option<String>,
}

fn query_value(target: &str, name: &str) -> Option<String> {
    form_urlencoded_pairs(target.split_once('?')?.1)
        .into_iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v)
}

struct Pending {
    client_id: String,

    scope: String,
    redirect_host: String,

    revisit: bool,
}

async fn pending_request(
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

fn is_local_path(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next() == Some(b'/')
        && !matches!(bytes.next(), Some(b'/' | b'\\'))
        && !value
            .chars()
            .any(|c| c == '\\' || c.is_control() || c.is_whitespace())
}

fn client_and_scope_of(target: &str) -> Option<(String, Option<String>, String)> {
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
        .map(|(k, v)| (percent_decode(k), percent_decode(v)))
        .collect()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }

            b'%' if i + 2 < bytes.len() => {
                match (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi << 4) | lo);
                        i += 3;
                    }

                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn new_session_id() -> Option<String> {
    let mut bytes = [0u8; 32];
    match ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes) {
        Ok(()) => Some(bytes.iter().map(|b| format!("{b:02x}")).collect()),
        Err(_) => None,
    }
}

fn no_entropy() -> Response {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::response::Html(PAGE_NO_SESSION.to_string()),
    )
        .into_response()
}

fn not_representable() -> Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        axum::response::Html(PAGE_NO_SESSION.to_string()),
    )
        .into_response()
}

fn not_found() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({ "error": "not_found" })),
    )
        .into_response()
}

const PAGE_NO_REQUEST: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>There is no authorization request waiting. Start the login from your agent.</p>";

const PAGE_NO_SESSION: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>This server could not start a session. Try again, and tell your operator if it persists.</p>";

const PAGE_UNRESOLVED_GRANT: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>This server could not resolve the requested permissions. Try again, and tell your operator \
    if it persists.</p>";

fn consent_page(return_to: &str, pending: &Pending) -> String {
    let scope = if pending.scope.is_empty() {
        "no scopes"
    } else {
        &pending.scope
    };
    let redirect_host = if pending.redirect_host.is_empty() {
        "(unnamed)"
    } else {
        &pending.redirect_host
    };

    let revisit = if pending.revisit {
        "<p id=\"revisit\">This request was shown before.</p>"
    } else {
        ""
    };
    format!(
        "<!doctype html><meta charset=utf-8><title>busbar — authorize</title>\
         <h1>Authorize this client?</h1>\
         <p>Client: <code>{client}</code></p>\
         <p>Requesting: <code>{scope}</code></p>\
         <p>Sends the credential to: <code>{host}</code></p>{revisit}\
         <form method=post>\
         <input type=hidden name=return value=\"{ret}\">\
         <button type=submit id=approve name=answer value=approve>Approve</button>\
         <button type=submit id=deny name=answer value=deny>Deny</button>\
         </form>",
        client = escape(&pending.client_id),
        scope = escape(scope),
        host = escape(redirect_host),
        ret = escape(return_to),
    )
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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
