// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MOUNT: which paths this plane serves, at what admission bar, and why each one is what it is.
//!
//! Every route here goes through [`crate::core_routes::CoreRouter`], which wires the handler and
//! declares its admission bar in the same act. `oauth-as` also ships an `axum` feature that hands
//! back a ready-made `Router`, and busbar does not use it: that router is a single `fallback`, so
//! its paths would enter the tree with NO entry in `CoreRouteTable` — and a served path the table
//! does not describe is the one state that table exists to make unrepresentable. The paths are
//! therefore registered here, concretely, derived from the operator's issuer at mount time, exactly
//! as the MCP plane registers its own.
//!
//! ## The bars, and the one that looks wrong until you read the RFC
//!
//! | route | bar | why |
//! |---|---|---|
//! | metadata, JWKS | `None` | RFC 8414 §3 and RFC 7517: read by a client that has no credential yet. Requiring one is a discovery loop with no entrance. |
//! | authorize | `None` | A browser endpoint. The resource owner is authenticated by the consent screen, and by nothing before it. |
//! | token, register | `None` | These carry OAuth's OWN client authentication in the request, which `oauth-as` performs. busbar's data-plane bar knows nothing about a `client_secret_post` body and would refuse every conforming client. |
//! | consent | `Admin` | The one route here that busbar authenticates itself, through the EXISTING admin chain. See [`super::consent`] on why the operator is the resource owner on this plane. |
//!
//! `RouteAuth::None` on four of them is not an absence of authentication; it is authentication that
//! belongs to a different protocol and is performed by the library that implements it. What it does
//! mean is that those four handlers must never read anything from busbar's governance state, and
//! they do not: each one forwards bytes to `oauth-as` and returns what it answers.

use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use busbar_plugin_loader::{RouteAuth, RouteMethod};

use crate::core_routes::CoreRouter;
use crate::state::AppHandle;

/// Mount the authorization server's routes, or none of them.
///
/// `None` returns the router untouched — no route, no table entry, nothing for the auth middleware
/// to consult. That is the zero-cost-when-off property at the routing layer.
pub(crate) fn mount(router: CoreRouter, plane: Option<&Arc<super::plane::AsPlane>>) -> CoreRouter {
    let Some(plane) = plane else {
        return router;
    };
    let id = plane.identity();
    let router = router
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
            forward,
        )
        .route(
            id.token_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
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
        );
    // RFC 7591 registration is mounted only when the operator turned it on. Absent rather than
    // present-and-refusing, because `oauth-as` derives its own route table from the metadata
    // document: an unadvertised `registration_endpoint` is one the library does not route either, so
    // a mounted-but-unadvertised path would 404 from underneath and read as a busbar bug.
    match id.register_path() {
        None => router,
        Some(path) => router.route(
            path.to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        ),
    }
}

/// Hand one request to `oauth-as` and return what it answers, unchanged.
///
/// The whole of busbar's OAuth wire surface is this function. Nothing is inspected, rewritten or
/// re-decided on the way through: the RFCs define these responses down to the header, and a gateway
/// that "improves" one of them is a gateway that fails a conformance suite for a reason nobody can
/// find.
async fn forward(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    request: axum::extract::Request,
) -> Response {
    let Some(plane) = app.oauth_as.as_ref() else {
        // Unreachable while the mount and the config are created in the same act, and a clean
        // refusal rather than an unwrap because this is a request path.
        return not_found();
    };
    plane
        .service()
        .handle(request)
        .await
        .map(|body| axum::body::Body::from(body.into_bytes()))
        .into_response()
}

/// `GET {issuer}/consent` — the screen that names the client and the scopes and asks the operator.
///
/// Reached ONLY after the admin chain has identified the caller, because the route declares
/// `RouteAuth::Admin`. There is therefore no credential check in this handler, and there must not
/// be: a second opinion about who an operator is, held by the authorization server, is the exact
/// duplication this plane was built not to have.
async fn consent_screen(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::extract::Query(query): axum::extract::Query<ConsentQuery>,
) -> Response {
    let Some(plane) = app.oauth_as.as_ref() else {
        return not_found();
    };
    let Some(target) = query.return_to.as_deref().filter(|t| is_local_path(t)) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::response::Html(PAGE_NO_REQUEST.to_string()),
        )
            .into_response();
    };
    // The session is opened HERE, not at the POST: the operator has already been authenticated by
    // the admin chain to get this far, so this is the moment the fact is true. The id is opaque and
    // unguessable, and it is the value the cookie carries.
    let id = new_session_id();
    plane.sessions().open(ADMIN_SUBJECT, id.clone());
    let page = consent_page(target);
    (
        [
            (
                axum::http::header::SET_COOKIE,
                format!(
                    "{}={id}; Path={}; HttpOnly; SameSite=Lax; Max-Age=600",
                    super::consent::SESSION_COOKIE,
                    plane.identity().consent_path()
                ),
            ),
            // A page naming a client and a scope set is a per-request answer. Cached, it would show
            // the next request's operator a previous request's decision.
            (axum::http::header::CACHE_CONTROL, "no-store".to_string()),
        ],
        axum::response::Html(page),
    )
        .into_response()
}

/// `POST {issuer}/consent` — the operator approved. Stake ONE approval and hand the browser back to
/// `/authorize`, which will spend it.
///
/// The approval is staked against the exact client and scope set the pending authorization request
/// carries, which the handler learns by re-reading the `return` URL it is about to redirect to
/// rather than from the form: a form field naming the scope would be a value the browser could
/// change between being shown one thing and approving another.
async fn consent_submit(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    headers: axum::http::HeaderMap,
    axum::extract::Form(form): axum::extract::Form<ConsentForm>,
) -> Response {
    let Some(plane) = app.oauth_as.as_ref() else {
        return not_found();
    };
    let Some(target) = form.return_to.as_deref().filter(|t| is_local_path(t)) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::response::Html(PAGE_NO_REQUEST.to_string()),
        )
            .into_response();
    };
    // The session comes from the COOKIE, never from the form. A form field naming the session
    // would be a value the page could be made to carry, which turns "the operator approved" into
    // "somebody submitted a form that says so".
    let Some(session) = super::consent::session_id(&headers) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::response::Html(PAGE_NO_REQUEST.to_string()),
        )
            .into_response();
    };
    if let Some((client_id, scope)) = client_and_scope_of(target) {
        plane
            .sessions()
            .stake(&session, format!("{client_id}\u{1f}{scope}"));
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

/// The subject an approval on this plane is granted BY. One value, because there is one party this
/// deployment can authenticate without an identity provider; see [`super::consent`].
const ADMIN_SUBJECT: &str = "busbar-operator";

/// `?return=` on the consent screen.
#[derive(serde::Deserialize)]
struct ConsentQuery {
    #[serde(rename = "return")]
    return_to: Option<String>,
}

/// The consent form's two fields.
#[derive(serde::Deserialize)]
struct ConsentForm {
    #[serde(rename = "return")]
    return_to: Option<String>,
}

/// Is this a path on THIS server rather than a URL somewhere else?
///
/// The consent screen redirects a browser to this value, so an unchecked one is an open redirect —
/// and an open redirect on an OAuth server's own origin is the single most useful thing an attacker
/// can find there. Accepted: a single leading `/` followed by something that is not another `/` and
/// not a `\`. Refused: an absolute URL, a scheme-relative `//evil.example`, and the backslash form
/// browsers normalise into one.
fn is_local_path(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && !value.starts_with("/\\")
        && !value.contains('\\')
}

/// The `client_id` and `scope` of a pending authorization request, read out of its query string.
///
/// Returns the RAW values: the approval key is compared against what `oauth-as` reports for the same
/// request, so the two only agree if nothing normalised one of them on the way past.
fn client_and_scope_of(target: &str) -> Option<(String, String)> {
    let query = target.split_once('?')?.1;
    let mut client_id = None;
    let mut scope = String::new();
    for (name, value) in form_urlencoded_pairs(query) {
        match name.as_str() {
            "client_id" => client_id = Some(value),
            "scope" => scope = value,
            _ => {}
        }
    }
    Some((client_id?, scope))
}

/// `a=b&c=d` with `+` and `%xx` decoded. Hand-written because the one caller reads two names out of
/// a query this server itself produced, and a general-purpose parser here would be a dependency
/// bought for eight lines.
fn form_urlencoded_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (percent_decode(k), percent_decode(v)))
        .collect()
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
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    // A stray `%` is kept verbatim rather than dropped: dropping it would let two
                    // different query strings decode to one value.
                    Err(_) => {
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

/// An unguessable session id. 256 bits from the platform RNG, hex.
fn new_session_id() -> String {
    let mut bytes = [0u8; 32];
    // A failure here means the platform has no entropy, which is not a condition to paper over with
    // a weaker id: the process is already unable to sign anything, so the caller gets a session that
    // cannot be opened and the operator retries.
    match ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes) {
        Ok(()) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        Err(_) => String::new(),
    }
}

fn not_found() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({ "error": "not_found" })),
    )
        .into_response()
}

/// What the operator sees when they land on the consent screen with no pending request — which is
/// what a bookmark, a refresh after approval, or a link somebody sent them all produce.
const PAGE_NO_REQUEST: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>There is no authorization request waiting. Start the login from your agent.</p>";

/// The consent screen.
///
/// Everything interpolated is HTML-escaped, and the client's name is NOT among the interpolations:
/// the screen names the `client_id` the request carried, because a `client_name` is a string the
/// client chose and a screen that renders it is a screen that can be made to say anything. The
/// registration policy refuses a name impersonating this deployment as well, which is defence in
/// depth rather than an alternative.
fn consent_page(return_to: &str) -> String {
    let (client_id, scope) =
        client_and_scope_of(return_to).unwrap_or_else(|| ("(unnamed)".to_string(), String::new()));
    let scope = if scope.is_empty() {
        "no scopes".to_string()
    } else {
        scope
    };
    format!(
        "<!doctype html><meta charset=utf-8><title>busbar — authorize</title>\
         <h1>Authorize this client?</h1>\
         <p>Client: <code>{client}</code></p>\
         <p>Requesting: <code>{scope}</code></p>\
         <form method=post>\
         <input type=hidden name=return value=\"{ret}\">\
         <button type=submit>Approve</button>\
         </form>",
        client = escape(&client_id),
        scope = escape(&scope),
        ret = escape(return_to),
    )
}

/// The five characters that change the meaning of surrounding markup.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Handlers take `Arc<AppHandle>` state through the `CurrentApp` extractor; naming the type here
/// keeps the mount signature honest about what it is building against.
type _State = Arc<AppHandle>;
