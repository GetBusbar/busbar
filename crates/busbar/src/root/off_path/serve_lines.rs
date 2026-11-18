// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stdio line session's lifecycle: its carrier, chosen once per process; its credential and
//! admission, once when the session opens; its drain deadline, once when it ends; and the session's
//! entry ([`serve_lines`], called once by `main` with `--stdio`), which picks the one line plane
//! ([`one_line_plane`], a start refusal when two declare it) and hands its lines to the request
//! path (`serve::lines::serve_port_lines`).

use std::sync::Arc;

use busbar_kernel::limits::process_admission::ProcessAdmission;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::root::serve::lines::{serve_port_lines, PORT_LINE_CARRIER};
use crate::root::serve::Served;

pub(crate) fn line_carrier(
    transports: &[crate::root::linked::LinkedTransport],
) -> Result<Option<&'static str>, String> {
    let mut lines = transports.iter().flat_map(|t| (t.lines)());
    let one = lines.next();
    match (one, lines.next()) {
        (Some(one), Some(other)) => {
            let refusal = format!(
                "the linked transport claims `{one}` and `{other}` both open a session on their first \
                 line, and the process's own stdin/stdout carries one"
            );
            Err(refusal)
        }
        (one, _) => Ok(one),
    }
}

/// The environment variable a line session's credential is read from. Every character outside
/// `[A-Z0-9_]` of the upper-cased words maps to `_`, so an identity-named instance still spells a
/// name a shell can export (WP1-GAP r3 §1.3, B-N11).
#[must_use]
pub(crate) fn env_credential(plane: &str, carrier: &str) -> String {
    let word = |w: &str| -> String {
        w.chars()
            .map(|c| c.to_ascii_uppercase())
            .map(|c| {
                if c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    format!("BUSBAR_{}_{}_CREDENTIAL", word(plane), word(carrier))
}

pub(crate) async fn session(
    app: Arc<busbar_kernel::state::App>,
    plane: &str,
    carrier: &str,
    audience: Option<&str>,
    credential: Option<&str>,
) -> Result<busbar_contract::records::PlaneRequestCtx, String> {
    let env = env_credential(plane, carrier);

    let Some(resource) = audience else {
        let refusal = format!(
            "this deployment's `{plane}:` block states no canonical resource, so a {carrier} session \
             has no audience to be bound to."
        );
        return Err(refusal);
    };

    if let Some(token) = credential {
        use busbar_kernel::auth::audience::Binding;
        match busbar_kernel::auth::audience::inspect_bearer(token, resource) {
            Binding::Deferred | Binding::Bound => {}
            Binding::Mismatch => {
                let refusal = format!(
                    "the credential in {env} carries an audience that does not identify this \
                     resource. Request a token whose `resource` (RFC 8707) is this deployment's \
                     `{plane}.canonical_uri`."
                );
                return Err(refusal);
            }
            Binding::Opaque => {
                let refusal = format!(
                    "the credential in {env} carries no readable audience, so it cannot be shown \
                     to have been issued for this resource. A busbar-signed key or a JWT access \
                     token bound to `{plane}.canonical_uri` is required."
                );
                return Err(refusal);
            }
        }
        if busbar_kernel::auth::dpop::refuse_bound_session(token, app.oauth_as.is_none()) {
            return Err(format!(
                "the credential in {env} is DPoP-bound (cnf.jkt), and a {carrier} session cannot \
                 carry a DPoP proof (RFC 9449), so it is refused. Set {env} to an unbound token."
            ));
        }
    }

    let admitted = busbar_kernel::auth::admit::admit_session(
        app,
        credential.map(str::to_string),
        resource.to_string(),
    );
    let admitted = admitted.await;
    match admitted {
        Ok((_principal, gov)) => {
            if !gov.is_governed() {
                eprintln!(
                    "[warn] {plane} {carrier} session is UNGOVERNED: no enforcement key is bound, so no \
                     budget applies and audit rows attribute to `anonymous`. Configure \
                     `auth.chain` and set {env} to bind the session to a key."
                );
            }
            Ok(gov)
        }
        Err(busbar_kernel::auth::IdentityRefusal::Denied) => {
            let refusal = if credential.is_none() {
                format!(
                "this deployment's `auth.chain` is configured, so an unauthenticated {carrier} session \
                 is refused exactly as an unauthenticated POST is. Set {env} to a credential the \
                 chain admits (audience-bound to `{plane}.canonical_uri`)."
                )
            } else {
                format!("the credential in {env} was refused by the auth chain.")
            };
            Err(refusal)
        }
        Err(busbar_kernel::auth::IdentityRefusal::NoGrant) => {
            let refusal = format!(
            "the credential in {env} authenticated, but its roles earned no enforcement key under \
             `role_bindings`, and an ungoverned admission would widen its access. The same request \
             over HTTP answers `insufficient_scope`."
            );
            Err(refusal)
        }
    }
}

/// The principal the session's carrier units run as, spelled once when the session opens.
pub(crate) fn session_principal(gov: &busbar_contract::records::PlaneRequestCtx) -> String {
    gov.key().map_or_else(
        || {
            busbar_contract::auth::AuthPrincipal(None)
                .actor_id()
                .to_string()
        },
        |k| k.id.clone(),
    )
}

/// When the session's remaining units are ended: the clock read once, as the session ends.
pub(crate) fn drain_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + busbar_kernel::detached::DETACHED_DRAIN_GRACE
}

pub(crate) async fn serve_lines(
    served: Served,
    app: Arc<busbar_kernel::state::AppHandle>,
    admission: Arc<ProcessAdmission>,
    stop: impl std::future::Future<Output = ()>,
) -> i32 {
    serve_lines_over(
        served,
        app,
        tokio::io::stdin(),
        tokio::io::stdout(),
        admission,
        stop,
    )
    .await
}

pub(crate) async fn serve_lines_over<R, W, S>(
    served: Served,
    app: Arc<busbar_kernel::state::AppHandle>,
    reader: R,
    writer: W,
    admission: Arc<ProcessAdmission>,
    stop: S,
) -> i32
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    S: std::future::Future<Output = ()>,
{
    let serving: Vec<(&str, bool)> = served
        .ports
        .iter()
        .map(|seat| (seat.instance.as_str(), seat.driver.serves_lines()))
        .collect();
    match one_line_plane(&serving) {
        Ok(Some(at)) => {
            let seat = served.ports[at].clone();
            serve_port_lines(seat, app, reader, writer, admission, stop).await
        }
        // Boot judged `--stdio` before any instance opened (WP1-GAP r3 §1.3); a generation that
        // lost its one line plane since is refused the same way, never served elsewhere.
        Ok(None) => {
            eprintln!(
                "busbar: {}",
                busbar_plugin_loader::instance::plane_sections::StdioRefusal::None
            );
            1
        }
        Err(refusal) => {
            eprintln!("busbar: {PORT_LINE_CARRIER} serve refused to start: {refusal}");
            1
        }
    }
}

/// IF §12.23 rule 1: the one served plane instance declaring ROUTE_LINE (`serving` = each instance's configured
/// name and whether it declares one), by its place. None = no line serving; two or more refuse the start, naming both.
pub(crate) fn one_line_plane(serving: &[(&str, bool)]) -> Result<Option<usize>, String> {
    let mut lines = serving.iter().enumerate().filter(|(_, (_, line))| *line);
    match (lines.next(), lines.next()) {
        (Some((_, (one, _))), Some((_, (other, _)))) => Err(format!(
            "the plane instances `{one}` and `{other}` both open a session on their first line, and the \
             process's own stdin/stdout carries one"
        )),
        (one, _) => Ok(one.map(|(at, _)| at)),
    }
}
