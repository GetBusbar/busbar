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
        )
        // RFC 7591 registration, mounted UNCONDITIONALLY: the 1.6.0 ruling is that all three
        // registration mechanisms are on whenever the plane is, with no toggles. The advertised
        // `registration_endpoint` in `policy::registration_config` is likewise unconditional, so
        // the metadata document and the route table cannot disagree about this path.
        .route(
            id.register_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        )
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
    // Box::pin: the whole `oauth-as` dispatch future (~56 KB monomorphized), boxed at its one call
    // site — cold relative to the data planes, and boxing keeps this handler's future small; see
    // the walk.rs precedent.
    Box::pin(plane.service().handle(request))
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
    //
    // NO SESSION WITHOUT ENTROPY. `new_session_id` answers `None` when the platform RNG failed, and
    // the refusal is the point: the previous code substituted an EMPTY id, which `Sessions::open`
    // would have stored happily and which any request could then present, because an empty cookie
    // value is not a secret anybody has to guess.
    let Some(id) = new_session_id() else {
        return no_entropy();
    };
    plane.sessions().open(ADMIN_SUBJECT, id.clone());
    let page = consent_page(target);

    let mut response = axum::response::Html(page).into_response();
    let headers = response.headers_mut();
    for cookie in session_cookies(plane.identity(), &id) {
        // `HeaderValue::from_str` rather than an unwrap, and the refusal is not theatre: the `Path`
        // is derived from the operator's `issuer`, whose path component is not character-checked at
        // boot, so a control character there would be a response-splitting vector. Refused whole.
        let Ok(value) = axum::http::HeaderValue::from_str(&cookie) else {
            return not_representable();
        };
        // APPEND, not insert: there is more than one cookie and the second must not replace the
        // first. See `session_cookies` for why there is more than one.
        headers.append(axum::http::header::SET_COOKIE, value);
    }
    // A page naming a client and a scope set is a per-request answer. Cached, it would show the
    // next request's operator a previous request's decision.
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// EVERY `Set-Cookie` that opens one consent session, and why there is more than one of them.
///
/// A cookie is only sent to the paths RFC 6265 §5.1.4 path-matches, which is a PREFIX match at a
/// `/` boundary — so a cookie scoped to `/consent` is never sent to `/authorize`. The two paths are
/// siblings, and the session is read at BOTH:
///
/// | reader | path | what reads it |
/// |---|---|---|
/// | the approval, and the resource owner behind it | `{issuer}/authorize` | [`super::consent::subject_resolver`] and [`super::consent::approval_resolver`], which `oauth-as` calls from its authorization handler |
/// | the approval submission | `{issuer}/consent` | [`consent_submit`], which takes the session from the cookie and never from the form |
///
/// That is the WHOLE list: it is the two mounts in [`mount`] whose handlers reach a
/// `session_id(...)` call, and no other mounted path does. The metadata document, the JWKS, the
/// token endpoint and the registration endpoint never read it — and the token endpoint is the one
/// that matters, because it is spoken to by the CLIENT rather than by the browser and a session
/// cookie arriving there would be an operator's credential handed to a party the flow exists to
/// keep it from.
///
/// So the narrowest scope that works is not one path, it is these TWO exact paths — one
/// `Set-Cookie` each. `Path=/` would be one line shorter and would send this cookie to every route
/// busbar serves, including the token endpoint above and every data-plane path on the same origin;
/// `Path={issuer}/` is the same mistake wearing a prefix. Two cookies of one name at two disjoint
/// paths is unambiguous by construction: no request path can match both, so no request ever carries
/// two of them, and [`super::consent::session_id`] never has to choose.
pub(super) fn session_cookies(identity: &super::config::AsIdentity, id: &str) -> [String; 2] {
    // `Secure` follows the ISSUER'S SCHEME rather than being unconditional. Unconditional would be
    // the stricter-looking choice and it would break the `http://` deployment outright — a browser
    // discards a `Secure` cookie arriving over plain HTTP, so the flow would fail exactly as it did
    // before this fix, and it would fail in a way that looks like a busbar bug rather than like a
    // deployment that is not using TLS. An `https:` issuer is the production posture and gets the
    // attribute; an `http:` one is a developer's loopback and gets a cookie that works.
    let secure = if identity.issuer().starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    // `SameSite=Lax`, NOT `Strict`. The browser arrives at `/authorize` by a top-level navigation
    // from the client's own site, which is cross-site: `Strict` withholds the cookie on exactly
    // that hop and would reintroduce this defect from the other end. `Lax` sends it on a top-level
    // GET navigation and withholds it from cross-site POSTs, which is what the consent submission
    // needs — that POST is same-site, issued by a form on this server's own page.
    //
    // `Max-Age` is `SESSION_TTL`, so the browser stops presenting a session at the moment the
    // server stops honouring it; a longer cookie would send a credential that is already dead.
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
    // The redirect host is rendered on the screen but deliberately NOT part of the stake key: the
    // key has to match what the authorization endpoint compares when it spends the approval, and
    // widening it here alone would make every approval unspendable.
    if let Some((client_id, scope, _redirect_host)) = client_and_scope_of(target) {
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
fn client_and_scope_of(target: &str) -> Option<(String, String, String)> {
    let query = target.split_once('?')?.1;
    let mut client_id = None;
    let mut scope = String::new();
    let mut redirect_uri = String::new();
    for (name, value) in form_urlencoded_pairs(query) {
        match name.as_str() {
            "client_id" => client_id = Some(value),
            "scope" => scope = value,
            "redirect_uri" => redirect_uri = value,
            _ => {}
        }
    }
    Some((client_id?, scope, host_of(&redirect_uri)))
}

/// The host authority of an absolute `redirect_uri` — the part of it an operator can judge.
///
/// The consent screen names this rather than the whole URI: the host is what decides WHO receives
/// the credential, and a full URI puts an attacker-chosen path and query on the screen next to it,
/// which is room to write text that argues with the page around it.
fn host_of(redirect_uri: &str) -> String {
    let after_scheme = redirect_uri
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(redirect_uri);
    // Authority ends at the first `/`, `?` or `#`; userinfo before an `@` is stripped, so a
    // `https://client.example@evil.example/cb` reads as `evil.example`, which is the host the
    // browser will actually contact.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority)
        .to_string()
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

/// An unguessable session id. 256 bits from the platform RNG, hex — or `None`.
///
/// `None` rather than a fallback string, and that is the whole of the change: the previous version
/// answered `String::new()` when the RNG failed, and an EMPTY session id is one every caller
/// already knows. It would have been opened as a live session, set as `busbar_as_session=`, and
/// accepted from anyone who sent the same empty value. A session id is a bearer credential, and the
/// only safe answer to "I could not generate a secret" is to not issue one.
fn new_session_id() -> Option<String> {
    let mut bytes = [0u8; 32];
    match ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes) {
        Ok(()) => Some(bytes.iter().map(|b| format!("{b:02x}")).collect()),
        Err(_) => None,
    }
}

/// The platform RNG failed, so no session was opened. A 503 rather than a page that pretends: the
/// operator's next action is to retry, and the deployment is in a state where it cannot sign a
/// token either.
fn no_entropy() -> Response {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::response::Html(PAGE_NO_SESSION.to_string()),
    )
        .into_response()
}

/// A `Set-Cookie` this deployment's own configuration cannot express as a header value — which
/// means a control character in the operator's `issuer` path. Refused whole rather than emitted
/// partially, because a half-written `Set-Cookie` is a response-splitting primitive.
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

/// What the operator sees when they land on the consent screen with no pending request — which is
/// what a bookmark, a refresh after approval, or a link somebody sent them all produce.
const PAGE_NO_REQUEST: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>There is no authorization request waiting. Start the login from your agent.</p>";

/// What the operator sees when this server could not open a session at all. It names no cause: the
/// two ways to get here are a failed platform RNG and a malformed issuer, and neither is something
/// a browser should be told about.
const PAGE_NO_SESSION: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>This server could not start a session. Try again, and tell your operator if it persists.</p>";

/// The consent screen.
///
/// Everything interpolated is HTML-escaped, and the client's name is NOT among the interpolations:
/// the screen names the `client_id` the request carried, because a `client_name` is a string the
/// client chose and a screen that renders it is a screen that can be made to say anything. The
/// registration policy refuses a name impersonating this deployment as well, which is defence in
/// depth rather than an alternative.
fn consent_page(return_to: &str) -> String {
    let (client_id, scope, redirect_host) = client_and_scope_of(return_to)
        .unwrap_or_else(|| ("(unnamed)".to_string(), String::new(), String::new()));
    let scope = if scope.is_empty() {
        "no scopes".to_string()
    } else {
        scope
    };
    let redirect_host = if redirect_host.is_empty() {
        "(unnamed)".to_string()
    } else {
        redirect_host
    };
    format!(
        "<!doctype html><meta charset=utf-8><title>busbar — authorize</title>\
         <h1>Authorize this client?</h1>\
         <p>Client: <code>{client}</code></p>\
         <p>Requesting: <code>{scope}</code></p>\
         <p>Sends the credential to: <code>{host}</code></p>\
         <form method=post>\
         <input type=hidden name=return value=\"{ret}\">\
         <button type=submit>Approve</button>\
         </form>",
        client = escape(&client_id),
        scope = escape(&scope),
        host = escape(&redirect_host),
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
