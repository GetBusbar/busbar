// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operator approval pages (#140): the RFC 8628 device verification page and the consent page.
//!
//! They live on the ADMIN listener at fixed paths ([`crate::config::OPERATOR_DEVICE_PATH`],
//! [`crate::config::OPERATOR_CONSENT_PATH`]), declared `RouteAuth::Admin` by
//! `mount::seam_mount_operator`: the contract keeps every Admin route physically off the data
//! listener, and the admin listener is loopback by default precisely so an open admin posture is not
//! public. Off the data listener's request path: an operator visits them a few times per login.
//!
//! Both pages are forms an operator's browser posts back, so both carry a store-kept CSRF token
//! bound to the page's own cookie and to WHAT the form answers, and both refuse a submission that
//! did not come from a page on the admin origin.

use axum::response::{IntoResponse, Response};

use crate::config::{OPERATOR_CONSENT_PATH, OPERATOR_DEVICE_PATH};
use crate::routes::{
    as_plane, client_and_scope_of, is_local_path, no_entropy, not_found, not_representable,
    pending_request, query_value, unresolved_grant, Escaped, Pending, PAGE_NO_REQUEST,
    PAGE_NO_SESSION,
};

/// The one resource owner of this plane: the operator.
const ADMIN_SUBJECT: &str = "busbar-operator";

/// The device page's form cookie, on the admin origin and scoped to the device page.
const DEVICE_FORM_COOKIE: &str = "busbar_as_device";

/// The consent page's form cookie, on the admin origin and scoped to the consent page.
const CONSENT_FORM_COOKIE: &str = "busbar_as_consent";

/// `?user_code=` on the device page.
#[derive(serde::Deserialize)]
pub(crate) struct DeviceQuery {
    user_code: Option<String>,
}

/// The device confirm form's fields.
#[derive(serde::Deserialize)]
pub(crate) struct DeviceForm {
    user_code: Option<String>,
    /// Held in wiping custody (credential typecheck; PM ruling 2026-11-17).
    csrf_token: Option<busbar_contract::secure::SecureString>,
    /// `approve` or `deny`; anything else shows the confirm page again.
    action: Option<String>,
}

/// `?return=&ref=` on the consent page: the pending request and the starting browser's session.
#[derive(serde::Deserialize)]
pub(crate) struct ConsentQuery {
    #[serde(rename = "return")]
    return_to: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
}

/// The consent form's fields.
#[derive(serde::Deserialize)]
pub(crate) struct ConsentForm {
    #[serde(rename = "return")]
    return_to: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
    /// Held in wiping custody (credential typecheck; PM ruling 2026-11-17).
    csrf_token: Option<busbar_contract::secure::SecureString>,
    /// `approve` or `deny`.
    answer: Option<String>,
}

/// `GET /oauth/device`: with no code, the code-entry form; with `?user_code=`, the confirm page that
/// names the client and the scope before any approve control exists (RFC 8628 s5.4).
pub(crate) async fn device_page(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    axum::extract::Query(query): axum::extract::Query<DeviceQuery>,
) -> Response {
    let Some(plane) = as_plane(&app) else {
        return not_found();
    };
    match query
        .user_code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        None => page(axum::http::StatusCode::OK, device_entry_page()),
        Some(code) => device_confirm(plane, code).await,
    }
}

/// `POST /oauth/device`: the operator's decision, from the confirm page on this origin, with its
/// single-use token. First decision wins (`approve_device`/`deny_device` compare-and-swap).
pub(crate) async fn device_decide(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    busbar_kernel::inbound::http_projection::ProjectedForm {
        headers,
        value: form,
    }: busbar_kernel::inbound::http_projection::ProjectedForm<DeviceForm>,
) -> Response {
    let Some(plane) = as_plane(&app) else {
        return not_found();
    };
    if !same_origin(&headers, plane.admin_origin()) {
        return forbidden();
    }
    let Some(code) = form
        .user_code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    else {
        return page(axum::http::StatusCode::BAD_REQUEST, PAGE_NO_CODE.into());
    };
    let consumed = match (
        crate::consent::cookie(&headers, DEVICE_FORM_COOKIE),
        form.csrf_token
            .as_ref()
            .map(busbar_contract::secure::SecureString::as_str)
            .filter(|t| !t.is_empty()),
    ) {
        (Some(id), Some(csrf)) => {
            match plane
                .consume_form(&id, &device_form_key(csrf, code), ADMIN_SUBJECT)
                .await
            {
                Ok(consumed) => consumed,
                Err(error) => {
                    tracing::warn!(%error, "oauth_as: the device form could not be consumed");
                    return store_unavailable();
                }
            }
        }
        _ => false,
    };
    if !consumed {
        return forbidden();
    }
    let decided = match form.action.as_deref() {
        Some("approve") => plane
            .server()
            .approve_device(code, ADMIN_SUBJECT)
            .await
            .map(|()| PAGE_APPROVED),
        Some("deny") => plane.server().deny_device(code).await.map(|()| PAGE_DENIED),
        _ => return device_confirm(plane, code).await,
    };
    match decided {
        Ok(result) => page(axum::http::StatusCode::OK, result.into()),
        Err(error) => device_refusal(&error),
    }
}

async fn device_confirm(plane: &crate::plane::AsPlane, code: &str) -> Response {
    let grant = match plane.pending_device(code).await {
        Ok(grant) => grant,
        Err(error) => return device_refusal(&error),
    };
    let (Some(form), Some(csrf)) = (crate::consent::new_handle(), crate::consent::new_handle())
    else {
        return no_entropy();
    };
    if let Err(error) = plane
        .issue_form(&form, &device_form_key(&csrf, code), ADMIN_SUBJECT)
        .await
    {
        tracing::warn!(%error, "oauth_as: the device form could not be kept");
        return store_unavailable();
    }
    let cookie = form_cookie(
        DEVICE_FORM_COOKIE,
        OPERATOR_DEVICE_PATH,
        &form,
        plane.admin_origin(),
        "Strict",
    );
    let Ok(cookie) = axum::http::HeaderValue::from_str(&cookie) else {
        return not_representable();
    };
    let mut response = page(
        axum::http::StatusCode::OK,
        device_confirm_page(&grant, &csrf),
    );
    response
        .headers_mut()
        .append(axum::http::header::SET_COOKIE, cookie);
    response
}

/// The device form's token names the user code it was issued for: a token shown for one code does
/// not decide another.
fn device_form_key(csrf: &str, code: &str) -> String {
    format!(
        "device-csrf:{csrf}\u{1f}{}",
        oauth_as::device::normalize_user_code(code)
    )
}

fn device_refusal(error: &oauth_as::DeviceApprovalError) -> Response {
    use axum::http::StatusCode;
    let (status, text) = match error {
        oauth_as::DeviceApprovalError::UnknownUserCode => (
            StatusCode::NOT_FOUND,
            "That code is not recognised. Check the code on your device and try again.",
        ),
        oauth_as::DeviceApprovalError::Expired => (
            StatusCode::GONE,
            "That code has expired. Start again on your device.",
        ),
        oauth_as::DeviceApprovalError::NotPending => (
            StatusCode::CONFLICT,
            "That code was already approved or denied.",
        ),
        oauth_as::DeviceApprovalError::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many codes were tried. Wait a minute and try again.",
        ),
        oauth_as::DeviceApprovalError::Storage(e) => {
            tracing::warn!(error = %e, "oauth_as: the device grant could not be read");
            return store_unavailable();
        }
        _ => (
            StatusCode::BAD_REQUEST,
            "That code cannot be approved. Start again on your device.",
        ),
    };
    page(
        status,
        format!(
            "<!doctype html><meta charset=utf-8><title>busbar — device</title>\
             <p>{}</p><p><a href=\"{OPERATOR_DEVICE_PATH}\">Enter another code</a></p>",
            Escaped(text)
        ),
    )
}

/// `GET /oauth/consent?return=&ref=`: the consent screen, reached by a cross-site 302 from the
/// authorization endpoint. Its form token is bound to `(ref, return)` and to a cookie this response
/// sets (`SameSite=Lax`: none can be expected on arrival).
pub(crate) async fn consent_screen(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    axum::extract::Query(query): axum::extract::Query<ConsentQuery>,
) -> Response {
    let Some(plane) = as_plane(&app) else {
        return not_found();
    };
    let (Some(target), Some(reference)) = (
        query.return_to.as_deref().filter(|t| is_local_path(t)),
        query
            .reference
            .as_deref()
            .filter(|r| crate::consent::is_handle(r)),
    ) else {
        return page(axum::http::StatusCode::BAD_REQUEST, PAGE_NO_REQUEST.into());
    };
    let pending = match pending_request(plane, target).await {
        Ok(pending) => pending,
        Err(error) => return unresolved_grant(&error),
    };
    let (Some(form), Some(csrf)) = (crate::consent::new_handle(), crate::consent::new_handle())
    else {
        return no_entropy();
    };
    if let Err(error) = plane
        .issue_form(
            &form,
            &consent_form_key(&csrf, reference, target),
            ADMIN_SUBJECT,
        )
        .await
    {
        tracing::warn!(%error, "oauth_as: the consent form could not be kept");
        return store_unavailable();
    }
    let cookie = form_cookie(
        CONSENT_FORM_COOKIE,
        OPERATOR_CONSENT_PATH,
        &form,
        plane.admin_origin(),
        "Lax",
    );
    let Ok(cookie) = axum::http::HeaderValue::from_str(&cookie) else {
        return not_representable();
    };
    let mut response = page(
        axum::http::StatusCode::OK,
        consent_page(target, reference, &csrf, &pending),
    );
    response
        .headers_mut()
        .append(axum::http::header::SET_COOKIE, cookie);
    response
}

/// `POST /oauth/consent`: the operator's answer. Opens the operator session under `ref`, stakes the
/// answer there bound to a fresh one-time T, and sends the browser back to the authorization
/// endpoint with T appended. Only the browser holding the start cookie `ref` names, presenting
/// that T, can spend it.
pub(crate) async fn consent_submit(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    busbar_kernel::inbound::http_projection::ProjectedForm {
        headers,
        value: form,
    }: busbar_kernel::inbound::http_projection::ProjectedForm<ConsentForm>,
) -> Response {
    let Some(plane) = as_plane(&app) else {
        return not_found();
    };
    if !same_origin(&headers, plane.admin_origin()) {
        return forbidden();
    }
    let (Some(target), Some(reference)) = (
        form.return_to.as_deref().filter(|t| is_local_path(t)),
        form.reference
            .as_deref()
            .filter(|r| crate::consent::is_handle(r)),
    ) else {
        return page(axum::http::StatusCode::BAD_REQUEST, PAGE_NO_REQUEST.into());
    };
    let approve = match form.answer.as_deref() {
        Some("approve") => true,
        Some("deny") => false,
        None | Some(_) => {
            return page(axum::http::StatusCode::BAD_REQUEST, PAGE_NO_REQUEST.into());
        }
    };
    // The token was issued for exactly this `(ref, return)`: fields that differ from what the
    // screen showed do not match it, so they are never trusted on their own.
    let consumed = match (
        crate::consent::cookie(&headers, CONSENT_FORM_COOKIE),
        form.csrf_token
            .as_ref()
            .map(busbar_contract::secure::SecureString::as_str)
            .filter(|t| !t.is_empty()),
    ) {
        (Some(id), Some(csrf)) => {
            match plane
                .consume_form(
                    &id,
                    &consent_form_key(csrf, reference, target),
                    ADMIN_SUBJECT,
                )
                .await
            {
                Ok(consumed) => consumed,
                Err(error) => {
                    tracing::warn!(%error, "oauth_as: the consent form could not be consumed");
                    return store_unavailable();
                }
            }
        }
        _ => false,
    };
    if !consumed {
        return forbidden();
    }
    let Some(handle) = crate::consent::new_handle() else {
        return no_entropy();
    };
    if let Err(error) = plane
        .open_session(ADMIN_SUBJECT, reference.to_string())
        .await
    {
        tracing::warn!(%error, "oauth_as: the consent session could not be kept");
        return store_unavailable();
    }
    if let Some((client_id, _scope, _redirect_host)) = client_and_scope_of(target) {
        let key = match query_value(target, "request_uri") {
            Some(request_uri) => crate::consent::pushed_key(&client_id, &request_uri),
            None => crate::consent::request_key(&client_id, target),
        };
        if let Err(error) = plane
            .stake(
                reference,
                crate::consent::handled_key(&key, &handle),
                approve,
            )
            .await
        {
            tracing::warn!(%error, "oauth_as: the consent answer could not be kept");
            return store_unavailable();
        }
    }
    let separator = if target.contains('?') { '&' } else { '?' };
    let back = format!(
        "{}{target}{separator}{}={handle}",
        plane.identity().origin(),
        crate::consent::HANDLE_PARAM
    );
    let Ok(mut back) = axum::http::HeaderValue::from_str(&back) else {
        return not_representable();
    };
    // The Location carries the one-time consent handle: never indexed or logged as plain.
    back.set_sensitive(true);
    (
        axum::http::StatusCode::FOUND,
        [
            (axum::http::header::LOCATION, back),
            (
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            ),
            (
                axum::http::header::REFERRER_POLICY,
                axum::http::HeaderValue::from_static("no-referrer"),
            ),
        ],
    )
        .into_response()
}

/// The consent form's token names the starting browser and the request it answers.
fn consent_form_key(csrf: &str, reference: &str, target: &str) -> String {
    format!("consent-csrf:{csrf}\u{1f}{reference}\u{1f}{target}")
}

/// Whether this POST came from a page on the admin origin. `Sec-Fetch-Site` is decisive where the
/// browser sends it; otherwise `Origin` must name the admin origin. Absence is refused: a browser
/// sends at least one of them on every form POST.
fn same_origin(headers: &axum::http::HeaderMap, admin_origin: &str) -> bool {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return site.eq_ignore_ascii_case("same-origin");
    }
    headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|origin| origin.eq_ignore_ascii_case(admin_origin))
}

fn form_cookie(name: &str, path: &str, id: &str, admin_origin: &str, same_site: &str) -> String {
    let secure = if admin_origin.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{name}={id}; Path={path}; HttpOnly{secure}; SameSite={same_site}; Max-Age={}",
        crate::consent::SESSION_TTL.as_secs(),
    )
}

/// An operator page: never cached, never framed, never named in a `Referer`.
fn page(status: axum::http::StatusCode, html: String) -> Response {
    let mut response = (status, crate::page::Page(html)).into_response();
    let headers = response.headers_mut();
    for (name, value) in [
        (axum::http::header::CACHE_CONTROL, "no-store"),
        (axum::http::header::REFERRER_POLICY, "no-referrer"),
    ] {
        headers.insert(name, axum::http::HeaderValue::from_static(value));
    }
    response
}

fn forbidden() -> Response {
    page(axum::http::StatusCode::FORBIDDEN, PAGE_FORBIDDEN.into())
}

fn store_unavailable() -> Response {
    page(
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        PAGE_NO_SESSION.into(),
    )
}

const PAGE_FORBIDDEN: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>This form has expired or did not come from this page. Go back, reload it and try again.</p>";

const PAGE_NO_CODE: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>Enter the code your device shows.</p>";

const PAGE_APPROVED: &str = "<!doctype html><meta charset=utf-8><title>busbar — device</title>\
    <p>Approved. Your device can continue.</p>";

const PAGE_DENIED: &str = "<!doctype html><meta charset=utf-8><title>busbar — device</title>\
    <p>The request was denied.</p>";

fn device_entry_page() -> String {
    format!(
        "<!doctype html><meta charset=utf-8><title>busbar — device</title>\
         <h1>Connect a device</h1>\
         <form method=get action=\"{OPERATOR_DEVICE_PATH}\">\
         <label>Code shown on your device: \
         <input name=\"user_code\" autocomplete=off autofocus required></label>\
         <button type=submit>Continue</button>\
         </form>"
    )
}

fn device_confirm_page(grant: &oauth_as::DeviceGrant, csrf: &str) -> String {
    let scope = grant.scope.to_string();
    let scope = if scope.is_empty() {
        "no scopes"
    } else {
        &scope
    };
    format!(
        "<!doctype html><meta charset=utf-8><title>busbar — device</title>\
         <h1>Connect this device?</h1>\
         <p>Code: <code>{code}</code></p>\
         <p>Client: <code>{client}</code></p>\
         <p>Requesting: <code>{scope}</code></p>\
         <form method=post action=\"{OPERATOR_DEVICE_PATH}\">\
         <input type=hidden name=\"user_code\" value=\"{code}\">\
         <input type=hidden name=\"csrf_token\" value=\"{csrf}\">\
         <button type=submit name=\"action\" value=\"approve\">Approve</button>\
         <button type=submit name=\"action\" value=\"deny\">Deny</button>\
         </form>",
        code = Escaped(&grant.user_code),
        client = Escaped(grant.client_id.as_str()),
        scope = Escaped(scope),
        csrf = Escaped(csrf),
    )
}

fn consent_page(return_to: &str, reference: &str, csrf: &str, pending: &Pending) -> String {
    // The page's own text (built once for the page, as the page itself is).
    let shown = pending.scope.to_string();
    let scope = if shown.is_empty() {
        "no scopes"
    } else {
        &shown
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
         <form method=post action=\"{OPERATOR_CONSENT_PATH}\">\
         <input type=hidden name=return value=\"{ret}\">\
         <input type=hidden name=ref value=\"{reference}\">\
         <input type=hidden name=\"csrf_token\" value=\"{csrf}\">\
         <button type=submit id=approve name=answer value=approve>Approve</button>\
         <button type=submit id=deny name=answer value=deny>Deny</button>\
         </form>",
        client = Escaped(&pending.client_id),
        scope = Escaped(scope),
        host = Escaped(redirect_host),
        ret = Escaped(return_to),
        reference = Escaped(reference),
        csrf = Escaped(csrf),
    )
}
